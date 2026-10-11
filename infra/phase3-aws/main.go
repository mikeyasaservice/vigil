package main

import (
	"fmt"

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

		provider, err := aws.NewProvider(ctx, "tenant-aws", &aws.ProviderArgs{
			Region:            pulumi.String(binding.Region),
			AllowedAccountIds: pulumi.StringArray{pulumi.String(binding.AccountID)},
			AssumeRoles: aws.ProviderAssumeRoleArray{aws.ProviderAssumeRoleArgs{
				RoleArn:     pulumi.String(binding.RoleARN),
				ExternalId:  pulumi.ToSecret(pulumi.String(binding.ExternalID)).(pulumi.StringOutput).ToStringPtrOutput(),
				SessionName: pulumi.String(fmt.Sprintf("vigil-%s", manifest.DeploymentID)), SourceIdentity: pulumi.String(manifest.DeploymentID),
			}},
			DefaultTags: &aws.ProviderDefaultTagsArgs{Tags: pulumi.StringMap{
				"vigil.io/tenant": pulumi.String(manifest.TenantID), "vigil.io/deployment": pulumi.String(manifest.DeploymentID),
				"vigil.io/incarnation": pulumi.String(manifest.Incarnation), "vigil.io/managed": pulumi.String("true"),
			}},
		})
		if err != nil {
			return err
		}

		deployment, err := tenant.NewDeployment(ctx, "vigil-"+manifest.DeploymentID, tenant.DeploymentArgs{
			Manifest: manifest, Binding: binding, Provider: provider,
		}, pulumi.Provider(provider))
		if err != nil {
			return err
		}

		ctx.Export("manifestDigest", pulumi.String(digest))
		ctx.Export("tenantId", pulumi.String(manifest.TenantID))
		ctx.Export("deploymentId", pulumi.String(manifest.DeploymentID))
		ctx.Export("generation", pulumi.Int(int(manifest.Generation)))
		ctx.Export("vpcId", deployment.VpcID)
		ctx.Export("clusterName", deployment.ClusterName)
		ctx.Export("databaseIdentifier", deployment.DatabaseIdentifier)
		ctx.Export("redisIdentifier", deployment.RedisIdentifier)
		ctx.Export("evidenceBucket", deployment.EvidenceBucket)
		ctx.Export("keyArn", deployment.KeyARN)
		return nil
	})
}
