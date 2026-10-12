package main

import (
	"fmt"
	"net/url"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"

	"vigil-managed-dedicated-aws/internal/spec"
	"vigil-managed-dedicated-aws/internal/tenant"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		cfg := config.New(ctx, "")
		manifestPath := cfg.Require("manifestPath")
		bindingPath := cfg.Require("bindingPath")
		manifest, binding, digest, err := spec.Load(manifestPath, bindingPath)
		if err != nil {
			return err
		}

		defaultTags := pulumi.StringMap{
			"vigil.io/tenant": pulumi.String(manifest.TenantID), "vigil.io/deployment": pulumi.String(manifest.DeploymentID),
			"vigil.io/incarnation": pulumi.String(manifest.Incarnation), "vigil.io/managed": pulumi.String("true"),
		}
		providerArgs := &aws.ProviderArgs{
			Region:      pulumi.String(binding.Region),
			DefaultTags: &aws.ProviderDefaultTagsArgs{Tags: defaultTags},
		}
		if binding.ExecutionProfile == "localstack" {
			endpoint := pulumi.String(binding.LocalStackEndpoint)
			providerArgs.AccessKey = pulumi.String("test")
			providerArgs.SecretKey = pulumi.String("test")
			providerArgs.S3UsePathStyle = pulumi.Bool(true)
			providerArgs.SkipCredentialsValidation = pulumi.Bool(true)
			providerArgs.SkipMetadataApiCheck = pulumi.Bool(true)
			providerArgs.SkipRegionValidation = pulumi.Bool(true)
			providerArgs.SkipRequestingAccountId = pulumi.Bool(true)
			providerArgs.SharedConfigFiles = pulumi.StringArray{}
			providerArgs.SharedCredentialsFiles = pulumi.StringArray{}
			providerArgs.Endpoints = aws.ProviderEndpointArray{aws.ProviderEndpointArgs{
				Ec2: endpoint, Kms: endpoint, S3: endpoint, Secretsmanager: endpoint, Sqs: endpoint, Sts: endpoint,
			}}
		} else {
			defaultTags["vigil.io/expires-at"] = pulumi.String(binding.ResourceExpiresAt)
			providerArgs.AllowedAccountIds = pulumi.StringArray{pulumi.String(binding.AccountID)}
			providerArgs.AssumeRoles = aws.ProviderAssumeRoleArray{aws.ProviderAssumeRoleArgs{
				RoleArn: pulumi.String(binding.RoleARN), ExternalId: pulumi.ToSecret(pulumi.String(binding.ExternalID)).(pulumi.StringOutput).ToStringPtrOutput(),
				SessionName: pulumi.String(fmt.Sprintf("vigil-%s", manifest.DeploymentID)),
			}}
		}
		provider, err := aws.NewProvider(ctx, "tenant-aws", providerArgs)
		if err != nil {
			return err
		}

		ctx.Export("manifestDigest", pulumi.String(digest))
		ctx.Export("tenantId", pulumi.String(manifest.TenantID))
		ctx.Export("deploymentId", pulumi.String(manifest.DeploymentID))
		ctx.Export("generation", pulumi.Int(int(manifest.Generation)))
		ctx.Export("executionProfile", pulumi.String(binding.ExecutionProfile))
		spiffe, err := url.Parse(binding.ReconcilerSPIFFEID)
		if err != nil || spiffe.Scheme != "spiffe" || spiffe.Host == "" {
			return fmt.Errorf("reconciler SPIFFE trust domain is invalid")
		}
		ctx.Export(
			"supportGatewaySpiffeId",
			pulumi.String(fmt.Sprintf("spiffe://%s/support-gateway/%s", spiffe.Host, manifest.DeploymentID)),
		)
		if binding.ExecutionProfile == "localstack" {
			deployment, createErr := tenant.NewLocalStackDeployment(ctx, "vigil-"+manifest.DeploymentID, tenant.DeploymentArgs{
				Manifest: manifest, Binding: binding, Provider: provider,
			}, pulumi.Provider(provider))
			if createErr != nil {
				return createErr
			}
			ctx.Export("vpcId", deployment.VpcID)
			ctx.Export("evidenceBucket", deployment.EvidenceBucket)
			ctx.Export("keyArn", deployment.KeyARN)
			ctx.Export("queueUrl", deployment.QueueURL)
			ctx.Export("runtimeSecretArn", deployment.RuntimeSecretARN)
			return nil
		}
		deployment, err := tenant.NewDeployment(ctx, "vigil-"+manifest.DeploymentID, tenant.DeploymentArgs{Manifest: manifest, Binding: binding, Provider: provider}, pulumi.Provider(provider))
		if err != nil {
			return err
		}
		ctx.Export("vpcId", deployment.VpcID)
		ctx.Export("clusterName", deployment.ClusterName)
		ctx.Export("databaseIdentifier", deployment.DatabaseIdentifier)
		ctx.Export("redisIdentifier", deployment.RedisIdentifier)
		ctx.Export("evidenceBucket", deployment.EvidenceBucket)
		ctx.Export("keyArn", deployment.KeyARN)
		ctx.Export("databaseEndpoint", deployment.DatabaseEndpoint)
		ctx.Export("redisEndpoint", deployment.RedisEndpoint)
		ctx.Export("runtimeSecretArn", deployment.RuntimeSecretARN)
		ctx.Export("kubeconfig", pulumi.ToSecret(deployment.Kubeconfig))
		ctx.Export("imageRepositories", deployment.ImageRepositories)
		ctx.Export("externalSecretsRoleArn", deployment.ExternalSecretsRoleARN)
		return nil
	})
}
