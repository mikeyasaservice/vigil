package main

import (
	"encoding/json"
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
	"github.com/pulumi/pulumi-random/sdk/v4/go/random"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func document(value any) (pulumi.String, error) {
	raw, err := json.Marshal(value)
	return pulumi.String(raw), err
}

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		cfg := config.New(ctx, "")
		accountID := cfg.Require("accountId")
		region := cfg.Require("region")
		trustedPrincipalARN := cfg.Require("trustedPrincipalArn")
		expiresAt := cfg.Require("expiresAt")
		provider, err := aws.NewProvider(ctx, "bootstrap-aws", &aws.ProviderArgs{
			Profile: pulumi.String("pulumi"), Region: pulumi.String(region),
			AllowedAccountIds: pulumi.StringArray{pulumi.String(accountID)},
			DefaultTags: &aws.ProviderDefaultTagsArgs{Tags: pulumi.StringMap{
				"vigil.io/managed": pulumi.String("true"), "vigil.io/purpose": pulumi.String("production-qualification"),
				"vigil.io/expires-at": pulumi.String(expiresAt),
			}},
		})
		if err != nil {
			return err
		}
		deploymentPolicy, err := document(map[string]any{
			"Version": "2012-10-17",
			"Statement": []map[string]any{
				{"Sid": "TenantInfrastructure", "Effect": "Allow", "Action": []string{
					"ec2:*", "eks:*", "rds:*", "elasticache:*", "autoscaling:*", "elasticloadbalancing:*",
					"kms:*", "s3:*", "secretsmanager:*", "ecr:*", "logs:*", "cloudwatch:*", "tag:GetResources", "ssm:GetParameter",
				}, "Resource": "*", "Condition": map[string]any{"StringEquals": map[string]string{"aws:RequestedRegion": region}}},
				{"Sid": "CallerAndInventory", "Effect": "Allow", "Action": []string{"sts:GetCallerIdentity", "iam:GetRole", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:List*"}, "Resource": "*"},
				{"Sid": "ManagedWorkloadIdentity", "Effect": "Allow", "Action": []string{
					"iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy",
					"iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:PassRole",
					"iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile",
					"iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile", "iam:GetInstanceProfile", "iam:TagInstanceProfile",
				}, "Resource": []string{fmt.Sprintf("arn:aws:iam::%s:role/vigil-*", accountID), fmt.Sprintf("arn:aws:iam::%s:instance-profile/vigil-*", accountID)}},
				{"Sid": "ManagedOidcProvider", "Effect": "Allow", "Action": []string{
					"iam:CreateOpenIDConnectProvider", "iam:DeleteOpenIDConnectProvider", "iam:GetOpenIDConnectProvider",
					"iam:TagOpenIDConnectProvider", "iam:UntagOpenIDConnectProvider", "iam:UpdateOpenIDConnectProviderThumbprint",
				}, "Resource": fmt.Sprintf("arn:aws:iam::%s:oidc-provider/*", accountID)},
				{"Sid": "RequiredServiceLinkedRoles", "Effect": "Allow", "Action": "iam:CreateServiceLinkedRole", "Resource": "*", "Condition": map[string]any{
					"StringEquals": map[string]any{"iam:AWSServiceName": []string{"eks.amazonaws.com", "eks-nodegroup.amazonaws.com", "rds.amazonaws.com", "elasticache.amazonaws.com", "autoscaling.amazonaws.com"}},
				}},
			},
		})
		if err != nil {
			return err
		}
		roles := pulumi.StringMap{}
		externalIDs := pulumi.StringMap{}
		for _, tenant := range []string{"a", "b"} {
			tenantID := "tenant-qual-" + tenant
			externalID, createErr := random.NewRandomPassword(ctx, "tenant-"+tenant+"-external-id", &random.RandomPasswordArgs{
				Length: pulumi.Int(48), Special: pulumi.Bool(false),
			})
			if createErr != nil {
				return createErr
			}
			trust := externalID.Result.ApplyT(func(id string) (string, error) {
				doc, marshalErr := document(map[string]any{
					"Version": "2012-10-17", "Statement": []map[string]any{{
						"Effect": "Allow", "Principal": map[string]string{"AWS": trustedPrincipalARN},
						"Action":    []string{"sts:AssumeRole", "sts:SetSourceIdentity"},
						"Condition": map[string]any{"StringEquals": map[string]string{"sts:ExternalId": id}},
					}},
				})
				return string(doc), marshalErr
			}).(pulumi.StringOutput)
			role, createErr := iam.NewRole(ctx, "tenant-"+tenant+"-deployer", &iam.RoleArgs{
				Name: pulumi.String("vigil-qual-" + tenant + "-deployer"), AssumeRolePolicy: trust,
				MaxSessionDuration: pulumi.Int(3600), Tags: pulumi.StringMap{
					"vigil.io/tenant":     pulumi.String("tenant-qual-" + tenant),
					"vigil.io/deployment": pulumi.String("deployment-qual-" + tenant),
				},
			}, pulumi.Provider(provider))
			if createErr != nil {
				return createErr
			}
			if _, createErr = iam.NewRolePolicy(ctx, "tenant-"+tenant+"-deployer-policy", &iam.RolePolicyArgs{
				Role: role.ID(), Policy: deploymentPolicy,
			}, pulumi.Provider(provider)); createErr != nil {
				return createErr
			}
			boundaryPolicy, marshalErr := document(map[string]any{
				"Version": "2012-10-17",
				"Statement": []map[string]any{
					{
						"Sid": "DenyResourcesOwnedByAnotherTenant", "Effect": "Deny",
						"Action": "*", "Resource": "*",
						"Condition": map[string]any{
							"Null":            map[string]string{"aws:ResourceTag/vigil.io/tenant": "false"},
							"StringNotEquals": map[string]string{"aws:ResourceTag/vigil.io/tenant": tenantID},
						},
					},
					{
						"Sid": "DenyRequestsForAnotherTenant", "Effect": "Deny",
						"Action": "*", "Resource": "*",
						"Condition": map[string]any{
							"Null":            map[string]string{"aws:RequestTag/vigil.io/tenant": "false"},
							"StringNotEquals": map[string]string{"aws:RequestTag/vigil.io/tenant": tenantID},
						},
					},
				},
			})
			if marshalErr != nil {
				return marshalErr
			}
			if _, createErr = iam.NewRolePolicy(ctx, "tenant-"+tenant+"-boundary-policy", &iam.RolePolicyArgs{
				Role: role.ID(), Policy: boundaryPolicy,
			}, pulumi.Provider(provider)); createErr != nil {
				return createErr
			}
			roles[tenant] = role.Arn
			externalIDs[tenant] = externalID.Result
		}
		ctx.Export("roleArns", roles)
		ctx.Export("externalIds", pulumi.ToSecret(externalIDs))
		ctx.Export("expiresAt", pulumi.String(expiresAt))
		return nil
	})
}
