package tenant

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/secretsmanager"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/sqs"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// LocalStackDeployment is an executable development contract for tenant-owned AWS
// resources. It deliberately does not pretend to provision EKS, RDS, or ElastiCache.
type LocalStackDeployment struct {
	pulumi.ResourceState
	VpcID            pulumi.IDOutput
	EvidenceBucket   pulumi.StringOutput
	KeyARN           pulumi.StringOutput
	QueueURL         pulumi.StringOutput
	RuntimeSecretARN pulumi.StringOutput
}

func NewLocalStackDeployment(ctx *pulumi.Context, name string, args DeploymentArgs, opts ...pulumi.ResourceOption) (*LocalStackDeployment, error) {
	component := &LocalStackDeployment{}
	if err := ctx.RegisterComponentResource("vigil:managed:LocalStackDeployment", name, component, opts...); err != nil {
		return nil, err
	}
	child := func(extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
		base := []pulumi.ResourceOption{pulumi.Parent(component), pulumi.Provider(args.Provider)}
		return append(base, extra...)
	}
	commonTags := tags(args.Manifest, args.Binding)
	key, err := kms.NewKey(ctx, name+"-data", &kms.KeyArgs{
		Description: pulumi.String("Tenant-local Vigil LocalStack development key"),
		Tags:        commonTags,
	}, child()...)
	if err != nil {
		return nil, err
	}

	vpc, err := ec2.NewVpc(ctx, name+"-vpc", &ec2.VpcArgs{
		CidrBlock: pulumi.String(args.Binding.VpcCIDR), EnableDnsHostnames: pulumi.Bool(true), EnableDnsSupport: pulumi.Bool(true), Tags: commonTags,
	}, child()...)
	if err != nil {
		return nil, err
	}
	for index, zone := range args.Binding.PermittedAvailabilityZones[:2] {
		_, err = ec2.NewSubnet(ctx, fmt.Sprintf("%s-private-%d", name, index), &ec2.SubnetArgs{
			VpcId: vpc.ID(), AvailabilityZone: pulumi.String(zone), CidrBlock: pulumi.String(args.Binding.PrivateSubnetCIDRs[index]),
			MapPublicIpOnLaunch: pulumi.Bool(false), Tags: commonTags,
		}, child()...)
		if err != nil {
			return nil, err
		}
	}

	bucket, err := s3.NewBucketV2(ctx, name+"-evidence", &s3.BucketV2Args{ForceDestroy: pulumi.Bool(true), Tags: commonTags}, child()...)
	if err != nil {
		return nil, err
	}
	if _, err = s3.NewBucketVersioningV2(ctx, name+"-evidence-versioning", &s3.BucketVersioningV2Args{
		Bucket: bucket.ID(), VersioningConfiguration: &s3.BucketVersioningV2VersioningConfigurationArgs{Status: pulumi.String("Enabled")},
	}, child()...); err != nil {
		return nil, err
	}
	if _, err = s3.NewBucketServerSideEncryptionConfigurationV2(ctx, name+"-evidence-encryption", &s3.BucketServerSideEncryptionConfigurationV2Args{
		Bucket: bucket.ID(), Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
			s3.BucketServerSideEncryptionConfigurationV2RuleArgs{ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
				SseAlgorithm: pulumi.String("aws:kms"), KmsMasterKeyId: key.Arn,
			}},
		},
	}, child()...); err != nil {
		return nil, err
	}

	queue, err := sqs.NewQueue(ctx, name+"-managed-jobs", &sqs.QueueArgs{
		KmsMasterKeyId: key.Arn, MessageRetentionSeconds: pulumi.Int(1209600), VisibilityTimeoutSeconds: pulumi.Int(300), Tags: commonTags,
	}, child()...)
	if err != nil {
		return nil, err
	}
	secret, err := secretsmanager.NewSecret(ctx, name+"-runtime-binding", &secretsmanager.SecretArgs{
		Description: pulumi.String("Synthetic LocalStack runtime binding; never production credentials"), KmsKeyId: key.Arn, Tags: commonTags,
	}, child()...)
	if err != nil {
		return nil, err
	}
	if _, err = secretsmanager.NewSecretVersion(ctx, name+"-runtime-binding-v1", &secretsmanager.SecretVersionArgs{
		SecretId: secret.ID(), SecretString: pulumi.ToSecret(pulumi.Sprintf(`{"tenant_id":%q,"deployment_id":%q,"synthetic":true}`, args.Manifest.TenantID, args.Manifest.DeploymentID)).(pulumi.StringOutput),
	}, child()...); err != nil {
		return nil, err
	}

	component.VpcID = vpc.ID()
	component.EvidenceBucket = bucket.Bucket
	component.KeyARN = key.Arn
	component.QueueURL = queue.Url
	component.RuntimeSecretARN = secret.Arn
	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{
		"vpcId": component.VpcID, "evidenceBucket": component.EvidenceBucket, "keyArn": component.KeyARN,
		"queueUrl": component.QueueURL, "runtimeSecretArn": component.RuntimeSecretARN,
	}); err != nil {
		return nil, err
	}
	return component, nil
}
