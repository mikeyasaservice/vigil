package main

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/secretsmanager"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/sqs"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"

	"vigil-byoc-aws/internal/spec"
)

func localstackProviderArgs(endpoint, accountID string) *aws.ProviderArgs {
	value := pulumi.String(endpoint)
	return &aws.ProviderArgs{
		Region: pulumi.String("us-east-1"), AccessKey: pulumi.String(accountID), SecretKey: pulumi.String("localstack-only"),
		S3UsePathStyle: pulumi.Bool(true), SkipCredentialsValidation: pulumi.Bool(true), SkipMetadataApiCheck: pulumi.Bool(true),
		SkipRegionValidation: pulumi.Bool(true), SkipRequestingAccountId: pulumi.Bool(true),
		SharedConfigFiles: pulumi.StringArray{}, SharedCredentialsFiles: pulumi.StringArray{},
		Endpoints: aws.ProviderEndpointArray{aws.ProviderEndpointArgs{
			Kms: value, S3: value, Secretsmanager: value, Sqs: value, Sts: value,
		}},
	}
}

func realProviderArgs(region, profile, accountID string) *aws.ProviderArgs {
	return &aws.ProviderArgs{
		Region: pulumi.String(region), Profile: pulumi.String(profile),
		AllowedAccountIds:    pulumi.StringArray{pulumi.String(accountID)},
		SkipMetadataApiCheck: pulumi.Bool(true),
	}
}

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		cfg := config.New(ctx, "")
		executionProfile := cfg.Get("executionProfile")
		if executionProfile == "" {
			executionProfile = "localstack"
		}
		endpoint := cfg.Get("localstackEndpoint")
		accountID := cfg.Require("accountId")
		platformAccountID := cfg.Get("platformAccountId")
		region := cfg.Get("region")
		if region == "" {
			region = "us-east-1"
		}
		awsProfile := cfg.Get("awsProfile")
		tenantID := cfg.Require("tenantId")
		deploymentID := cfg.Require("deploymentId")
		acknowledgement := cfg.Require("ownershipAcknowledgement")
		if err := spec.Validate(executionProfile, endpoint, accountID, platformAccountID, tenantID, deploymentID, acknowledgement); err != nil {
			return err
		}
		providerConfig := localstackProviderArgs(endpoint, accountID)
		if executionProfile != "localstack" {
			providerConfig = realProviderArgs(region, awsProfile, accountID)
		}
		provider, err := aws.NewProvider(ctx, "customer-account", providerConfig, pulumi.Protect(false))
		if err != nil {
			return err
		}
		child := []pulumi.ResourceOption{pulumi.Provider(provider)}
		tags := pulumi.StringMap{
			"autobot.internal/tenant": pulumi.String(tenantID), "autobot.internal/deployment": pulumi.String(deploymentID),
			"autobot.internal/ownership": pulumi.String("customer"), "autobot.internal/mode": pulumi.String("byoc"),
		}
		key, err := kms.NewKey(ctx, "customer-data", &kms.KeyArgs{
			Description: pulumi.String("Customer-owned Autobot BYOC key"), Tags: tags,
			EnableKeyRotation: pulumi.Bool(true), DeletionWindowInDays: pulumi.Int(7),
		}, child...)
		if err != nil {
			return err
		}
		createBucket := func(name, suffix string) (*s3.BucketV2, error) {
			bucket, createErr := s3.NewBucketV2(ctx, name, &s3.BucketV2Args{
				Bucket: pulumi.String(fmt.Sprintf("autobot-byoc-%s-%s-%s", accountID, suffix, ctx.Stack())), ForceDestroy: pulumi.Bool(executionProfile != "aws"), Tags: tags,
			}, child...)
			if createErr != nil {
				return nil, createErr
			}
			_, createErr = s3.NewBucketPublicAccessBlock(ctx, name+"-public-access", &s3.BucketPublicAccessBlockArgs{
				Bucket: bucket.ID(), BlockPublicAcls: pulumi.Bool(true), BlockPublicPolicy: pulumi.Bool(true),
				IgnorePublicAcls: pulumi.Bool(true), RestrictPublicBuckets: pulumi.Bool(true),
			}, child...)
			if createErr != nil {
				return nil, createErr
			}
			_, createErr = s3.NewBucketVersioningV2(ctx, name+"-versioning", &s3.BucketVersioningV2Args{
				Bucket: bucket.ID(), VersioningConfiguration: &s3.BucketVersioningV2VersioningConfigurationArgs{Status: pulumi.String("Enabled")},
			}, child...)
			if createErr != nil {
				return nil, createErr
			}
			_, createErr = s3.NewBucketServerSideEncryptionConfigurationV2(ctx, name+"-encryption", &s3.BucketServerSideEncryptionConfigurationV2Args{
				Bucket: bucket.ID(), Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
					s3.BucketServerSideEncryptionConfigurationV2RuleArgs{ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
						SseAlgorithm: pulumi.String("aws:kms"), KmsMasterKeyId: key.Arn,
					}},
				},
			}, child...)
			return bucket, createErr
		}
		evidence, err := createBucket("evidence", "evidence")
		if err != nil {
			return err
		}
		backup, err := createBucket("backup", "backup")
		if err != nil {
			return err
		}
		queue, err := sqs.NewQueue(ctx, "execution", &sqs.QueueArgs{
			Name: pulumi.String("autobot-byoc-" + deploymentID), KmsMasterKeyId: key.Arn,
			VisibilityTimeoutSeconds: pulumi.Int(300), MessageRetentionSeconds: pulumi.Int(1209600), Tags: tags,
		}, child...)
		if err != nil {
			return err
		}
		secret, err := secretsmanager.NewSecret(ctx, "integration-reference", &secretsmanager.SecretArgs{
			Name: pulumi.String("autobot/byoc/" + deploymentID + "/integration"), KmsKeyId: key.Arn, Tags: tags,
		}, child...)
		if err != nil {
			return err
		}
		policy := pulumi.All(evidence.Arn, backup.Arn, queue.Arn, key.Arn, secret.Arn).ApplyT(func(values []any) (string, error) {
			return spec.RuntimePolicy(values[0].(string), values[1].(string), values[2].(string), values[3].(string), values[4].(string))
		}).(pulumi.StringOutput)
		ctx.Export("accountId", pulumi.String(accountID))
		ctx.Export("tenantId", pulumi.String(tenantID))
		ctx.Export("deploymentId", pulumi.String(deploymentID))
		ctx.Export("evidenceBucket", evidence.Bucket)
		ctx.Export("backupBucket", backup.Bucket)
		ctx.Export("executionQueueUrl", queue.Url)
		ctx.Export("keyArn", key.Arn)
		ctx.Export("integrationSecretArn", secret.Arn)
		ctx.Export("runtimePolicy", policy)
		ctx.Export("customerOwnedState", pulumi.Bool(true))
		ctx.Export("centralCredentialCopies", pulumi.Int(0))
		ctx.Export("executionProfile", pulumi.String(executionProfile))
		return nil
	})
}
