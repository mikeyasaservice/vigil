package connector

import (
	"context"
	"fmt"
	"time"
)

type DaemonConfig struct {
	HeartbeatInterval time.Duration
	RetryMinimum      time.Duration
	RetryMaximum      time.Duration
	RotateBefore      time.Duration
	CertPath          string
	CAPath            string
	TLSKeyPath        string
}

func Run(ctx context.Context, authority *Authority, client *Client, config DaemonConfig) error {
	if config.HeartbeatInterval <= 0 || config.RetryMinimum <= 0 || config.RetryMaximum < config.RetryMinimum {
		return fmt.Errorf("connector daemon timing is invalid")
	}
	retry := config.RetryMinimum
	nextHeartbeat := time.Now().UTC()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := time.Now().UTC()
		if !now.Before(nextHeartbeat) {
			state := authority.State()
			status := "healthy"
			if !state.ManagementEnabled {
				status = "revoked"
			}
			if err := authority.QueueHealth("heartbeat", HealthPayload{
				Status: status, ReleaseDigest: optionalDigest(state.InstalledRelease), BacklogCount: uint64(len(state.Outbox)),
			}, now); err != nil {
				return err
			}
			nextHeartbeat = now.Add(config.HeartbeatInterval)
		}
		if authority.State().ManagementEnabled && CertificateNeedsRotation(config.CertPath, config.RotateBefore, now) {
			csr, err := EnsureTLSKeyAndCSR(config.TLSKeyPath, authority.State().Binding.ConnectorSPIFFE)
			if err == nil {
				var certificate CertificateResponse
				certificate, err = client.RotateCertificate(ctx, authority.State().Binding.DeploymentID, csr)
				if err == nil {
					err = InstallCertificate(config.CertPath, config.CAPath, config.TLSKeyPath, authority.State().Binding.ConnectorSPIFFE, certificate)
				}
			}
			if err != nil {
				if !wait(ctx, retry) {
					return ctx.Err()
				}
				retry = minDuration(retry*2, config.RetryMaximum)
				continue
			}
		}
		event, ok := authority.OldestHealth()
		if !ok || !authority.State().ManagementEnabled {
			if !wait(ctx, minDuration(time.Until(nextHeartbeat), config.HeartbeatInterval)) {
				return ctx.Err()
			}
			continue
		}
		if _, err := client.SendHealth(ctx, authority.State().Binding.DeploymentID, event); err != nil {
			if !wait(ctx, retry) {
				return ctx.Err()
			}
			retry = minDuration(retry*2, config.RetryMaximum)
			continue
		}
		if err := authority.AckHealth(event.Sequence); err != nil {
			return err
		}
		retry = config.RetryMinimum
	}
}

func optionalDigest(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func wait(ctx context.Context, duration time.Duration) bool {
	if duration < 10*time.Millisecond {
		duration = 10 * time.Millisecond
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
