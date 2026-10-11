package tenant

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/elasticache"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/kms"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/rds"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/secretsmanager"
	ekscomponent "github.com/pulumi/pulumi-eks/sdk/v4/go/eks"
	"github.com/pulumi/pulumi-random/sdk/v4/go/random"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"vigil-managed-dedicated-aws/internal/spec"
)

type DeploymentArgs struct {
	Manifest spec.Manifest
	Binding  spec.Binding
	Provider *aws.Provider
}

type Deployment struct {
	pulumi.ResourceState
	VpcID              pulumi.IDOutput
	ClusterName        pulumi.StringOutput
	DatabaseIdentifier pulumi.StringOutput
	RedisIdentifier    pulumi.StringOutput
	EvidenceBucket     pulumi.StringOutput
	KeyARN             pulumi.StringOutput
}

func tags(m spec.Manifest) pulumi.StringMap {
	return pulumi.StringMap{
		"vigil.io/tenant":      pulumi.String(m.TenantID),
		"vigil.io/deployment":  pulumi.String(m.DeploymentID),
		"vigil.io/incarnation": pulumi.String(m.Incarnation),
		"vigil.io/managed":     pulumi.String("true"),
	}
}

func childOptions(component *Deployment, provider *aws.Provider, extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
	opts := []pulumi.ResourceOption{pulumi.Parent(component), pulumi.Provider(provider)}
	return append(opts, extra...)
}

func NewDeployment(ctx *pulumi.Context, name string, args DeploymentArgs, opts ...pulumi.ResourceOption) (*Deployment, error) {
	component := &Deployment{}
	if err := ctx.RegisterComponentResource("vigil:managed:DedicatedDeployment", name, component, opts...); err != nil {
		return nil, err
	}

	commonTags := tags(args.Manifest)
	authenticationMode := ekscomponent.AuthenticationModeApiAndConfigMap
	key, err := kms.NewKey(ctx, name+"-data", &kms.KeyArgs{
		Description:          pulumi.String("Tenant-local Vigil data encryption"),
		EnableKeyRotation:    pulumi.Bool(true),
		DeletionWindowInDays: pulumi.Int(30),
		Tags:                 commonTags,
	}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}

	vpc, err := ec2.NewVpc(ctx, name+"-vpc", &ec2.VpcArgs{
		CidrBlock:          pulumi.String(args.Binding.VpcCIDR),
		EnableDnsHostnames: pulumi.Bool(true),
		EnableDnsSupport:   pulumi.Bool(true),
		InstanceTenancy:    pulumi.String("default"),
		Tags:               commonTags,
	}, childOptions(component, args.Provider, pulumi.Protect(true))...)
	if err != nil {
		return nil, err
	}

	igw, err := ec2.NewInternetGateway(ctx, name+"-igw", &ec2.InternetGatewayArgs{VpcId: vpc.ID(), Tags: commonTags}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	publicRT, err := ec2.NewRouteTable(ctx, name+"-public-rt", &ec2.RouteTableArgs{VpcId: vpc.ID(), Tags: commonTags}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	_, err = ec2.NewRoute(ctx, name+"-public-default", &ec2.RouteArgs{
		RouteTableId: publicRT.ID(), DestinationCidrBlock: pulumi.String("0.0.0.0/0"), GatewayId: igw.ID(),
	}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}

	var publicSubnets pulumi.StringArray
	var privateSubnets pulumi.StringArray
	for index, zone := range args.Binding.PermittedAvailabilityZones[:2] {
		publicSubnet, err := ec2.NewSubnet(ctx, fmt.Sprintf("%s-public-%d", name, index), &ec2.SubnetArgs{
			VpcId: vpc.ID(), AvailabilityZone: pulumi.String(zone), CidrBlock: pulumi.String(args.Binding.PublicSubnetCIDRs[index]),
			MapPublicIpOnLaunch: pulumi.Bool(false), Tags: commonTags,
		}, childOptions(component, args.Provider)...)
		if err != nil {
			return nil, err
		}
		if _, err = ec2.NewRouteTableAssociation(ctx, fmt.Sprintf("%s-public-rta-%d", name, index), &ec2.RouteTableAssociationArgs{
			SubnetId: publicSubnet.ID(), RouteTableId: publicRT.ID(),
		}, childOptions(component, args.Provider)...); err != nil {
			return nil, err
		}
		privateSubnet, err := ec2.NewSubnet(ctx, fmt.Sprintf("%s-private-%d", name, index), &ec2.SubnetArgs{
			VpcId: vpc.ID(), AvailabilityZone: pulumi.String(zone), CidrBlock: pulumi.String(args.Binding.PrivateSubnetCIDRs[index]),
			MapPublicIpOnLaunch: pulumi.Bool(false), Tags: commonTags,
		}, childOptions(component, args.Provider)...)
		if err != nil {
			return nil, err
		}
		publicSubnets = append(publicSubnets, publicSubnet.ID())
		privateSubnets = append(privateSubnets, privateSubnet.ID())

		eip, err := ec2.NewEip(ctx, fmt.Sprintf("%s-nat-eip-%d", name, index), &ec2.EipArgs{
			Domain: pulumi.String("vpc"), Tags: commonTags,
		}, childOptions(component, args.Provider, pulumi.DependsOn([]pulumi.Resource{igw}))...)
		if err != nil {
			return nil, err
		}
		nat, err := ec2.NewNatGateway(ctx, fmt.Sprintf("%s-nat-%d", name, index), &ec2.NatGatewayArgs{
			AllocationId: eip.ID(), SubnetId: publicSubnet.ID(), Tags: commonTags,
		}, childOptions(component, args.Provider)...)
		if err != nil {
			return nil, err
		}
		privateRT, err := ec2.NewRouteTable(ctx, fmt.Sprintf("%s-private-rt-%d", name, index), &ec2.RouteTableArgs{
			VpcId: vpc.ID(), Tags: commonTags,
		}, childOptions(component, args.Provider)...)
		if err != nil {
			return nil, err
		}
		if _, err = ec2.NewRoute(ctx, fmt.Sprintf("%s-private-default-%d", name, index), &ec2.RouteArgs{
			RouteTableId: privateRT.ID(), DestinationCidrBlock: pulumi.String("0.0.0.0/0"), NatGatewayId: nat.ID(),
		}, childOptions(component, args.Provider)...); err != nil {
			return nil, err
		}
		if _, err = ec2.NewRouteTableAssociation(ctx, fmt.Sprintf("%s-private-rta-%d", name, index), &ec2.RouteTableAssociationArgs{
			SubnetId: privateSubnet.ID(), RouteTableId: privateRT.ID(),
		}, childOptions(component, args.Provider)...); err != nil {
			return nil, err
		}
	}

	cluster, err := ekscomponent.NewCluster(ctx, name+"-eks", &ekscomponent.ClusterArgs{
		VpcId: vpc.ID(), PrivateSubnetIds: privateSubnets, PublicSubnetIds: publicSubnets,
		EndpointPrivateAccess: pulumi.Bool(true), EndpointPublicAccess: pulumi.Bool(false),
		CreateOidcProvider: pulumi.Bool(true), EncryptionConfigKeyArn: key.Arn,
		EnabledClusterLogTypes:       pulumi.StringArray{pulumi.String("api"), pulumi.String("audit"), pulumi.String("authenticator"), pulumi.String("controllerManager"), pulumi.String("scheduler")},
		NodeAssociatePublicIpAddress: pulumi.BoolRef(false), NodeRootVolumeEncrypted: pulumi.Bool(true),
		NodeRootVolumeSize: pulumi.Int(100), InstanceType: pulumi.String("m7i.large"),
		DesiredCapacity: pulumi.Int(2), MinSize: pulumi.Int(2), MaxSize: pulumi.Int(4),
		DeletionProtection: pulumi.Bool(true), AuthenticationMode: &authenticationMode,
		Version: pulumi.String("1.36"),
		Tags: commonTags,
	}, append(childOptions(component, args.Provider), pulumi.Providers(args.Provider))...)
	if err != nil {
		return nil, err
	}

	dataSG, err := ec2.NewSecurityGroup(ctx, name+"-data-sg", &ec2.SecurityGroupArgs{
		VpcId: vpc.ID(), Description: pulumi.String("Tenant-local database and cache from dedicated nodes"), Tags: commonTags,
	}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	for port, label := range map[int]string{5432: "postgres", 6379: "redis"} {
		_, err = ec2.NewSecurityGroupRule(ctx, fmt.Sprintf("%s-%s-from-nodes", name, label), &ec2.SecurityGroupRuleArgs{
			Type: pulumi.String("ingress"), Protocol: pulumi.String("tcp"), FromPort: pulumi.Int(port), ToPort: pulumi.Int(port),
			SecurityGroupId: dataSG.ID(), SourceSecurityGroupId: cluster.NodeSecurityGroupId,
		}, childOptions(component, args.Provider)...)
		if err != nil {
			return nil, err
		}
	}

	dbSubnets, err := rds.NewSubnetGroup(ctx, name+"-db-subnets", &rds.SubnetGroupArgs{SubnetIds: privateSubnets, Tags: commonTags}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	database, err := rds.NewInstance(ctx, name+"-postgres", &rds.InstanceArgs{
		Engine: pulumi.String("postgres"), EngineVersion: pulumi.String("16.15"), InstanceClass: pulumi.String("db.m7g.large"),
		AllocatedStorage: pulumi.Int(100), MaxAllocatedStorage: pulumi.Int(1000), StorageType: pulumi.String("gp3"),
		StorageEncrypted: pulumi.Bool(true), KmsKeyId: key.Arn, DbSubnetGroupName: dbSubnets.Name,
		VpcSecurityGroupIds: pulumi.StringArray{dataSG.ID()}, PubliclyAccessible: pulumi.Bool(false), MultiAz: pulumi.Bool(true),
		DbName: pulumi.String("vigil"), Username: pulumi.String("vigil_admin"), ManageMasterUserPassword: pulumi.Bool(true), MasterUserSecretKmsKeyId: key.Arn,
		BackupRetentionPeriod: pulumi.Int(14), CopyTagsToSnapshot: pulumi.Bool(true), DeletionProtection: pulumi.Bool(true),
		SkipFinalSnapshot: pulumi.Bool(false), FinalSnapshotIdentifier: pulumi.Sprintf("%s-final", name),
		PerformanceInsightsEnabled: pulumi.Bool(true), PerformanceInsightsKmsKeyId: key.Arn, PerformanceInsightsRetentionPeriod: pulumi.Int(7),
		AutoMinorVersionUpgrade: pulumi.Bool(true), ApplyImmediately: pulumi.Bool(false), Tags: commonTags,
	}, childOptions(component, args.Provider, pulumi.Protect(true))...)
	if err != nil {
		return nil, err
	}

	cacheSubnets, err := elasticache.NewSubnetGroup(ctx, name+"-cache-subnets", &elasticache.SubnetGroupArgs{SubnetIds: privateSubnets, Tags: commonTags}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	redisPassword, err := random.NewRandomPassword(ctx, name+"-redis-password", &random.RandomPasswordArgs{Length: pulumi.Int(48), Special: pulumi.Bool(false)}, pulumi.Parent(component))
	if err != nil {
		return nil, err
	}
	redisSecret, err := secretsmanager.NewSecret(ctx, name+"-redis-secret", &secretsmanager.SecretArgs{KmsKeyId: key.Arn, Tags: commonTags}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	if _, err = secretsmanager.NewSecretVersion(ctx, name+"-redis-secret-v1", &secretsmanager.SecretVersionArgs{
		SecretId: redisSecret.ID(), SecretString: redisPassword.Result,
	}, childOptions(component, args.Provider)...); err != nil {
		return nil, err
	}
	cache, err := elasticache.NewReplicationGroup(ctx, name+"-redis", &elasticache.ReplicationGroupArgs{
		Description: pulumi.String("Tenant-local Vigil queue and cache"), Engine: pulumi.String("redis"), EngineVersion: pulumi.String("7.1"),
		NodeType: pulumi.String("cache.r7g.large"), NumCacheClusters: pulumi.Int(2), AutomaticFailoverEnabled: pulumi.Bool(true), MultiAzEnabled: pulumi.Bool(true),
		SubnetGroupName: cacheSubnets.Name, SecurityGroupIds: pulumi.StringArray{dataSG.ID()},
		AtRestEncryptionEnabled: pulumi.Bool(true), TransitEncryptionEnabled: pulumi.Bool(true), TransitEncryptionMode: pulumi.String("required"),
		KmsKeyId: key.Arn, AuthTokenWo: redisPassword.Result, AuthTokenWoVersion: pulumi.Int(1),
		SnapshotRetentionLimit: pulumi.Int(7), AutoMinorVersionUpgrade: pulumi.Bool(true), ApplyImmediately: pulumi.Bool(false), Tags: commonTags,
	}, childOptions(component, args.Provider, pulumi.Protect(true))...)
	if err != nil {
		return nil, err
	}

	bucket, err := s3.NewBucketV2(ctx, name+"-evidence", &s3.BucketV2Args{ForceDestroy: pulumi.Bool(false), Tags: commonTags}, childOptions(component, args.Provider, pulumi.Protect(true))...)
	if err != nil {
		return nil, err
	}
	if _, err = s3.NewBucketVersioningV2(ctx, name+"-evidence-versioning", &s3.BucketVersioningV2Args{
		Bucket: bucket.ID(), VersioningConfiguration: &s3.BucketVersioningV2VersioningConfigurationArgs{Status: pulumi.String("Enabled")},
	}, childOptions(component, args.Provider)...); err != nil {
		return nil, err
	}
	if _, err = s3.NewBucketServerSideEncryptionConfigurationV2(ctx, name+"-evidence-encryption", &s3.BucketServerSideEncryptionConfigurationV2Args{
		Bucket: bucket.ID(), Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
			s3.BucketServerSideEncryptionConfigurationV2RuleArgs{ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{SseAlgorithm: pulumi.String("aws:kms"), KmsMasterKeyId: key.Arn}, BucketKeyEnabled: pulumi.Bool(true)},
		},
	}, childOptions(component, args.Provider)...); err != nil {
		return nil, err
	}
	if _, err = s3.NewBucketPublicAccessBlock(ctx, name+"-evidence-public-block", &s3.BucketPublicAccessBlockArgs{
		Bucket: bucket.ID(), BlockPublicAcls: pulumi.Bool(true), BlockPublicPolicy: pulumi.Bool(true), IgnorePublicAcls: pulumi.Bool(true), RestrictPublicBuckets: pulumi.Bool(true),
	}, childOptions(component, args.Provider)...); err != nil {
		return nil, err
	}

	component.VpcID = vpc.ID()
	component.ClusterName = cluster.EksCluster.Name()
	component.DatabaseIdentifier = database.Identifier
	component.RedisIdentifier = cache.ID().ToStringOutput()
	component.EvidenceBucket = bucket.Bucket
	component.KeyARN = key.Arn
	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{
		"vpcId": component.VpcID, "clusterName": component.ClusterName, "databaseIdentifier": component.DatabaseIdentifier,
		"redisIdentifier": component.RedisIdentifier, "evidenceBucket": component.EvidenceBucket, "keyArn": component.KeyARN,
	}); err != nil {
		return nil, err
	}
	return component, nil
}
