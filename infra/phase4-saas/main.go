package main

import (
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/sqs"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"

	"vigil-shared-saas/internal/cell"
)

func localStackProviderArgs(endpoint, accessKey string) *aws.ProviderArgs {
	return &aws.ProviderArgs{
		Region:                    pulumi.String("us-east-1"),
		AccessKey:                 pulumi.String(accessKey),
		SecretKey:                 pulumi.String("test"),
		S3UsePathStyle:            pulumi.Bool(true),
		SkipCredentialsValidation: pulumi.Bool(true),
		SkipMetadataApiCheck:      pulumi.Bool(true),
		SkipRegionValidation:      pulumi.Bool(true),
		SkipRequestingAccountId:   pulumi.Bool(true),
		SharedConfigFiles:         pulumi.StringArray{},
		SharedCredentialsFiles:    pulumi.StringArray{},
		Endpoints: aws.ProviderEndpointArray{aws.ProviderEndpointArgs{
			Kms: pulumi.String(endpoint), S3: pulumi.String(endpoint),
			Sqs: pulumi.String(endpoint), Sts: pulumi.String(endpoint),
		}},
	}
}

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		cfg := config.New(ctx, "")
		endpoint := cfg.Require("localstackEndpoint")
		if err := cell.ValidateLocalStackEndpoint(endpoint); err != nil {
			return err
		}
		var tenantIDs []string
		cfg.RequireObject("tenantIds", &tenantIDs)
		if err := cell.ValidateTenantIDs(tenantIDs); err != nil {
			return err
		}
		tenantIDs = cell.Sorted(tenantIDs)
		platformProvider, err := aws.NewProvider(
			ctx, "shared-cell-localstack", localStackProviderArgs(endpoint, "test"), pulumi.Protect(false),
		)
		if err != nil {
			return err
		}
		platformChild := []pulumi.ResourceOption{pulumi.Provider(platformProvider)}
		platformKey, err := kms.NewKey(ctx, "shared-metering", &kms.KeyArgs{
			Description: pulumi.String("Vigil shared SaaS aggregate metering key"),
			Tags:        pulumi.StringMap{"vigil.io/scope": pulumi.String("shared-management-metadata")},
		}, platformChild...)
		if err != nil {
			return err
		}
		metering, err := sqs.NewQueue(ctx, "shared-metering", &sqs.QueueArgs{
			Name: pulumi.String("vigil-shared-metering"), KmsMasterKeyId: platformKey.Arn,
			MessageRetentionSeconds: pulumi.Int(1209600),
			Tags:                    pulumi.StringMap{"vigil.io/scope": pulumi.String("shared-management-metadata")},
		}, platformChild...)
		if err != nil {
			return err
		}

		bucketOutputs := pulumi.Map{}
		queueOutputs := pulumi.Map{}
		accountOutputs := pulumi.Map{}
		policyOutputs := pulumi.Map{}
		for index, tenantID := range tenantIDs {
			name := strings.ReplaceAll(tenantID, "_", "-")
			accountID := fmt.Sprintf("%012d", index+1)
			tenantProvider, providerErr := aws.NewProvider(
				ctx, name+"-localstack", localStackProviderArgs(endpoint, accountID), pulumi.Protect(false),
			)
			if providerErr != nil {
				return providerErr
			}
			tenantChild := []pulumi.ResourceOption{pulumi.Provider(tenantProvider)}
			tags := pulumi.StringMap{
				"vigil.io/tenant": pulumi.String(tenantID), "vigil.io/cell": pulumi.String("cell-us-east-1"),
				"vigil.io/isolation": pulumi.String("dedicated-account-resource"),
			}
			key, createErr := kms.NewKey(ctx, name+"-data", &kms.KeyArgs{
				Description: pulumi.String("Tenant-bound shared-cell development key"), Tags: tags,
			}, tenantChild...)
			if createErr != nil {
				return createErr
			}
			bucket, createErr := s3.NewBucketV2(ctx, name+"-evidence", &s3.BucketV2Args{
				Bucket: pulumi.String(fmt.Sprintf("vigil-saas-%s-%s", tenantID, ctx.Stack())), ForceDestroy: pulumi.Bool(true), Tags: tags,
			}, tenantChild...)
			if createErr != nil {
				return createErr
			}
			_, createErr = s3.NewBucketPublicAccessBlock(ctx, name+"-evidence-public-access", &s3.BucketPublicAccessBlockArgs{
				Bucket: bucket.ID(), BlockPublicAcls: pulumi.Bool(true), BlockPublicPolicy: pulumi.Bool(true),
				IgnorePublicAcls: pulumi.Bool(true), RestrictPublicBuckets: pulumi.Bool(true),
			}, tenantChild...)
			if createErr != nil {
				return createErr
			}
			_, createErr = s3.NewBucketVersioningV2(ctx, name+"-evidence-versioning", &s3.BucketVersioningV2Args{
				Bucket: bucket.ID(), VersioningConfiguration: &s3.BucketVersioningV2VersioningConfigurationArgs{Status: pulumi.String("Enabled")},
			}, tenantChild...)
			if createErr != nil {
				return createErr
			}
			_, createErr = s3.NewBucketServerSideEncryptionConfigurationV2(ctx, name+"-evidence-encryption", &s3.BucketServerSideEncryptionConfigurationV2Args{
				Bucket: bucket.ID(), Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
					s3.BucketServerSideEncryptionConfigurationV2RuleArgs{ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
						SseAlgorithm: pulumi.String("aws:kms"), KmsMasterKeyId: key.Arn,
					}},
				},
			}, tenantChild...)
			if createErr != nil {
				return createErr
			}
			queue, createErr := sqs.NewQueue(ctx, name+"-jobs", &sqs.QueueArgs{
				Name: pulumi.String("vigil-saas-" + tenantID + "-jobs"), KmsMasterKeyId: key.Arn,
				VisibilityTimeoutSeconds: pulumi.Int(300), MessageRetentionSeconds: pulumi.Int(1209600), Tags: tags,
			}, tenantChild...)
			if createErr != nil {
				return createErr
			}
			bucketOutputs[tenantID] = bucket.Bucket
			queueOutputs[tenantID] = queue.Url
			accountOutputs[tenantID] = pulumi.String(accountID)
			policyOutputs[tenantID] = pulumi.All(bucket.Arn, queue.Arn, key.Arn, metering.Arn).ApplyT(
				func(values []any) (string, error) {
					return cell.RuntimePolicy(values[0].(string), values[1].(string), values[2].(string), values[3].(string))
				},
			).(pulumi.StringOutput)
		}
		ctx.Export("cellId", pulumi.String("cell-us-east-1"))
		ctx.Export("tenantBuckets", bucketOutputs)
		ctx.Export("tenantQueues", queueOutputs)
		ctx.Export("tenantAccounts", accountOutputs)
		ctx.Export("tenantRuntimePolicies", policyOutputs)
		ctx.Export("meteringQueueUrl", metering.Url)
		ctx.Export("dataPlaneSharing", pulumi.String("disabled-until-iam-qualified"))
		return nil
	})
}
