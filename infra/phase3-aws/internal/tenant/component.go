package tenant

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/ecr"
	awseks "github.com/pulumi/pulumi-aws/sdk/v7/go/aws/eks"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/elasticache"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/iam"
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
	VpcID                  pulumi.IDOutput
	ClusterName            pulumi.StringOutput
	DatabaseIdentifier     pulumi.StringOutput
	RedisIdentifier        pulumi.StringOutput
	EvidenceBucket         pulumi.StringOutput
	KeyARN                 pulumi.StringOutput
	DatabaseEndpoint       pulumi.StringOutput
	RedisEndpoint          pulumi.StringOutput
	RuntimeSecretARN       pulumi.StringOutput
	Kubeconfig             pulumi.StringOutput
	ImageRepositories      pulumi.StringMapOutput
	ExternalSecretsRoleARN pulumi.StringOutput
}

func tags(m spec.Manifest, b spec.Binding) pulumi.StringMap {
	values := pulumi.StringMap{
		"vigil.io/tenant":      pulumi.String(m.TenantID),
		"vigil.io/deployment":  pulumi.String(m.DeploymentID),
		"vigil.io/incarnation": pulumi.String(m.Incarnation),
		"vigil.io/managed":     pulumi.String("true"),
	}
	if b.ResourceExpiresAt != "" {
		values["vigil.io/expires-at"] = pulumi.String(b.ResourceExpiresAt)
	}
	return values
}

func childOptions(component *Deployment, provider *aws.Provider, extra ...pulumi.ResourceOption) []pulumi.ResourceOption {
	opts := []pulumi.ResourceOption{pulumi.Parent(component), pulumi.Provider(provider)}
	return append(opts, extra...)
}

func marshalJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	return string(raw), err
}

func NewDeployment(ctx *pulumi.Context, name string, args DeploymentArgs, opts ...pulumi.ResourceOption) (*Deployment, error) {
	component := &Deployment{}
	if err := ctx.RegisterComponentResource("vigil:managed:DedicatedDeployment", name, component, opts...); err != nil {
		return nil, err
	}

	commonTags := tags(args.Manifest, args.Binding)
	protected := args.Binding.LifecycleState == "active"
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
	repositoryURLs := pulumi.StringMap{}
	for _, workload := range []string{"backend", "daemon", "agent", "connector", "reasoner", "management"} {
		repository, createErr := ecr.NewRepository(ctx, name+"-"+workload, &ecr.RepositoryArgs{
			Name:               pulumi.String(fmt.Sprintf("vigil/%s/%s", args.Manifest.DeploymentID, workload)),
			ImageTagMutability: pulumi.String("IMMUTABLE"), ForceDelete: pulumi.Bool(!protected),
			ImageScanningConfiguration: &ecr.RepositoryImageScanningConfigurationArgs{ScanOnPush: pulumi.Bool(true)},
			EncryptionConfigurations: ecr.RepositoryEncryptionConfigurationArray{
				&ecr.RepositoryEncryptionConfigurationArgs{EncryptionType: pulumi.String("KMS"), KmsKey: key.Arn},
			},
			Tags: commonTags,
		}, childOptions(component, args.Provider, pulumi.Protect(protected))...)
		if createErr != nil {
			return nil, createErr
		}
		if _, createErr = ecr.NewLifecyclePolicy(ctx, name+"-"+workload+"-retention", &ecr.LifecyclePolicyArgs{
			Repository: repository.Name,
			Policy:     pulumi.String(`{"rules":[{"rulePriority":1,"description":"retain the most recent 20 immutable releases","selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":20},"action":{"type":"expire"}}]}`),
		}, childOptions(component, args.Provider)...); createErr != nil {
			return nil, createErr
		}
		repositoryURLs[workload] = repository.RepositoryUrl
	}

	vpc, err := ec2.NewVpc(ctx, name+"-vpc", &ec2.VpcArgs{
		CidrBlock:          pulumi.String(args.Binding.VpcCIDR),
		EnableDnsHostnames: pulumi.Bool(true),
		EnableDnsSupport:   pulumi.Bool(true),
		InstanceTenancy:    pulumi.String("default"),
		Tags:               commonTags,
	}, childOptions(component, args.Provider, pulumi.Protect(protected))...)
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
		EndpointPrivateAccess: pulumi.Bool(true), EndpointPublicAccess: pulumi.Bool(true),
		PublicAccessCidrs: pulumi.ToStringArray(args.Binding.ControlPlaneAccessCIDRs),
		ProviderCredentialOpts: ekscomponent.KubeconfigOptionsArgs{
			ProfileName: pulumi.String(args.Binding.KubeconfigCredentialProfile),
		},
		CreateOidcProvider: pulumi.Bool(true), EncryptionConfigKeyArn: key.Arn,
		EnabledClusterLogTypes:       pulumi.StringArray{pulumi.String("api"), pulumi.String("audit"), pulumi.String("authenticator"), pulumi.String("controllerManager"), pulumi.String("scheduler")},
		NodeAssociatePublicIpAddress: pulumi.BoolRef(false), NodeRootVolumeEncrypted: pulumi.Bool(true),
		NodeRootVolumeSize: pulumi.Int(100), InstanceType: pulumi.String("m7g.large"),
		DesiredCapacity: pulumi.Int(2), MinSize: pulumi.Int(2), MaxSize: pulumi.Int(4),
		UseDefaultVpcCni:   pulumi.BoolRef(false),
		VpcCniOptions:      &ekscomponent.VpcCniOptionsArgs{EnableNetworkPolicy: pulumi.Bool(true)},
		DeletionProtection: pulumi.Bool(protected), AuthenticationMode: &authenticationMode,
		Version: pulumi.String("1.36"),
		Tags:    commonTags,
	}, append(childOptions(component, args.Provider), pulumi.Providers(args.Provider))...)
	if err != nil {
		return nil, err
	}
	ebsPolicy, err := iam.NewRolePolicyAttachment(ctx, name+"-ebs-csi-node-policy", &iam.RolePolicyAttachmentArgs{
		Role:      cluster.InstanceRoles.Index(pulumi.Int(0)).Name(),
		PolicyArn: pulumi.String("arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"),
	}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	if _, err = awseks.NewAddon(ctx, name+"-ebs-csi", &awseks.AddonArgs{
		ClusterName:              cluster.EksCluster.Name(),
		AddonName:                pulumi.String("aws-ebs-csi-driver"),
		ResolveConflictsOnCreate: pulumi.StringPtr("OVERWRITE"),
		ResolveConflictsOnUpdate: pulumi.StringPtr("PRESERVE"),
		Tags:                     commonTags,
	}, childOptions(component, args.Provider, pulumi.DependsOn([]pulumi.Resource{ebsPolicy}))...); err != nil {
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
	databasePassword, err := random.NewRandomPassword(ctx, name+"-database-password", &random.RandomPasswordArgs{
		Length: pulumi.Int(48), Special: pulumi.Bool(false),
	}, pulumi.Parent(component))
	if err != nil {
		return nil, err
	}
	var finalSnapshotIdentifier pulumi.StringPtrInput
	if protected {
		finalSnapshotIdentifier = pulumi.Sprintf("%s-final", name).ToStringPtrOutput()
	}
	database, err := rds.NewCluster(ctx, name+"-postgres", &rds.ClusterArgs{
		Engine: pulumi.String("aurora-postgresql"), EngineMode: pulumi.String("provisioned"), EngineVersion: pulumi.String("16.9"),
		StorageEncrypted: pulumi.Bool(true), KmsKeyId: key.Arn, DbSubnetGroupName: dbSubnets.Name,
		VpcSecurityGroupIds: pulumi.StringArray{dataSG.ID()}, Port: pulumi.Int(5432),
		DatabaseName: pulumi.String("vigil"), MasterUsername: pulumi.String("vigil_admin"),
		MasterPasswordWo: databasePassword.Result, MasterPasswordWoVersion: pulumi.Int(1),
		BackupRetentionPeriod: pulumi.Int(14), CopyTagsToSnapshot: pulumi.Bool(true), DeletionProtection: pulumi.Bool(protected),
		SkipFinalSnapshot: pulumi.Bool(!protected), FinalSnapshotIdentifier: finalSnapshotIdentifier,
		IamDatabaseAuthenticationEnabled: pulumi.Bool(true),
		Serverlessv2ScalingConfiguration: &rds.ClusterServerlessv2ScalingConfigurationArgs{
			MinCapacity: pulumi.Float64(0), MaxCapacity: pulumi.Float64(8), SecondsUntilAutoPause: pulumi.Int(300),
		},
		ApplyImmediately: pulumi.Bool(false), Tags: commonTags,
	}, childOptions(component, args.Provider, pulumi.Protect(protected))...)
	if err != nil {
		return nil, err
	}
	for index, zone := range args.Binding.PermittedAvailabilityZones[:2] {
		if _, err = rds.NewClusterInstance(ctx, fmt.Sprintf("%s-postgres-%d", name, index), &rds.ClusterInstanceArgs{
			ClusterIdentifier: database.ID(), Engine: rds.EngineTypeAuroraPostgresql, EngineVersion: pulumi.String("16.9"),
			InstanceClass: pulumi.String("db.serverless"), AvailabilityZone: pulumi.String(zone),
			DbSubnetGroupName: dbSubnets.Name, PubliclyAccessible: pulumi.Bool(false),
			AutoMinorVersionUpgrade: pulumi.Bool(true), ApplyImmediately: pulumi.Bool(false),
			PerformanceInsightsEnabled: pulumi.Bool(true), PerformanceInsightsKmsKeyId: key.Arn,
			PerformanceInsightsRetentionPeriod: pulumi.Int(7), Tags: commonTags,
		}, childOptions(component, args.Provider, pulumi.Protect(protected))...); err != nil {
			return nil, err
		}
	}
	redisPassword, err := random.NewRandomPassword(ctx, name+"-redis-password", &random.RandomPasswordArgs{Length: pulumi.Int(48), Special: pulumi.Bool(false)}, pulumi.Parent(component))
	if err != nil {
		return nil, err
	}
	cacheUser, err := elasticache.NewUser(ctx, name+"-cache-user", &elasticache.UserArgs{
		UserId: pulumi.String(name + "-runtime"), UserName: pulumi.String("vigil"), Engine: pulumi.String("valkey"),
		AccessString: pulumi.String("on ~* +@all"), AuthenticationMode: &elasticache.UserAuthenticationModeArgs{
			Type: pulumi.String("password"), Passwords: pulumi.StringArray{redisPassword.Result},
		}, Tags: commonTags,
	}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	cacheGroup, err := elasticache.NewUserGroup(ctx, name+"-cache-users", &elasticache.UserGroupArgs{
		UserGroupId: pulumi.String(name + "-runtime"), Engine: pulumi.String("valkey"), UserIds: pulumi.StringArray{cacheUser.UserId}, Tags: commonTags,
	}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	cache, err := elasticache.NewServerlessCache(ctx, name+"-redis", &elasticache.ServerlessCacheArgs{
		Name: pulumi.String(name + "-runtime"), Description: pulumi.String("Tenant-local Vigil queue and cache"),
		Engine: pulumi.String("valkey"), MajorEngineVersion: pulumi.String("8"),
		SubnetIds: privateSubnets, SecurityGroupIds: pulumi.StringArray{dataSG.ID()}, UserGroupId: cacheGroup.UserGroupId,
		KmsKeyId: key.Arn, SnapshotRetentionLimit: pulumi.Int(7), Tags: commonTags,
	}, childOptions(component, args.Provider, pulumi.Protect(protected))...)
	if err != nil {
		return nil, err
	}

	jwtSecret, err := random.NewRandomPassword(ctx, name+"-jwt-secret", &random.RandomPasswordArgs{Length: pulumi.Int(64), Special: pulumi.Bool(false)}, pulumi.Parent(component))
	if err != nil {
		return nil, err
	}
	agentToken, err := random.NewRandomPassword(ctx, name+"-agent-token", &random.RandomPasswordArgs{Length: pulumi.Int(64), Special: pulumi.Bool(false)}, pulumi.Parent(component))
	if err != nil {
		return nil, err
	}
	reasonerToken, err := random.NewRandomPassword(ctx, name+"-reasoner-token", &random.RandomPasswordArgs{Length: pulumi.Int(64), Special: pulumi.Bool(false)}, pulumi.Parent(component))
	if err != nil {
		return nil, err
	}
	identityProxyToken, err := random.NewRandomPassword(ctx, name+"-identity-proxy-token", &random.RandomPasswordArgs{Length: pulumi.Int(64), Special: pulumi.Bool(false)}, pulumi.Parent(component))
	if err != nil {
		return nil, err
	}
	authoritySeed, err := random.NewRandomBytes(ctx, name+"-authority-seed", &random.RandomBytesArgs{Length: pulumi.Int(ed25519.SeedSize)}, pulumi.Parent(component))
	if err != nil {
		return nil, err
	}
	runtimeSecret, err := secretsmanager.NewSecret(ctx, name+"-runtime-binding", &secretsmanager.SecretArgs{
		Description: pulumi.String("Tenant-local Vigil runtime credentials"), KmsKeyId: key.Arn,
		RecoveryWindowInDays: pulumi.Int(30), Tags: commonTags,
	}, childOptions(component, args.Provider, pulumi.Protect(protected))...)
	if err != nil {
		return nil, err
	}
	cacheEndpoint := cache.Endpoints.Index(pulumi.Int(0)).Address()
	runtimePayload := pulumi.All(
		databasePassword.Result, redisPassword.Result, jwtSecret.Result, agentToken.Result,
		reasonerToken.Result, identityProxyToken.Result, authoritySeed.Base64, cacheEndpoint,
	).ApplyT(func(values []interface{}) (string, error) {
		seed, decodeErr := base64.StdEncoding.DecodeString(values[6].(string))
		if decodeErr != nil || len(seed) != ed25519.SeedSize {
			return "", fmt.Errorf("derive managed authority key: invalid seed")
		}
		privateKey := ed25519.NewKeyFromSeed(seed)
		payload := map[string]string{
			"POSTGRES_PASSWORD":     values[0].(string),
			"REDIS_URL":             fmt.Sprintf("rediss://vigil:%s@%s:6379/0", values[1].(string), values[7].(string)),
			"JWT_SECRET_KEY":        values[2].(string),
			"AGENT_INTERNAL_TOKEN":  values[3].(string),
			"reasoner-token":        values[4].(string),
			"token":                 values[5].(string),
			"authority-private-key": base64.RawURLEncoding.EncodeToString(seed),
			"authority-public-key":  base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		}
		raw, marshalErr := json.Marshal(payload)
		return string(raw), marshalErr
	}).(pulumi.StringOutput)
	if _, err = secretsmanager.NewSecretVersion(ctx, name+"-runtime-binding-v1", &secretsmanager.SecretVersionArgs{
		SecretId: runtimeSecret.ID(), SecretString: runtimePayload,
	}, childOptions(component, args.Provider)...); err != nil {
		return nil, err
	}
	externalSecretsTrust := pulumi.All(cluster.OidcProviderArn, cluster.OidcIssuer).ApplyT(func(values []interface{}) (string, error) {
		issuer := strings.TrimPrefix(values[1].(string), "https://")
		return marshalJSON(map[string]any{
			"Version": "2012-10-17", "Statement": []map[string]any{{
				"Effect": "Allow", "Principal": map[string]string{"Federated": values[0].(string)},
				"Action": "sts:AssumeRoleWithWebIdentity", "Condition": map[string]any{"StringEquals": map[string]string{
					issuer + ":sub": "system:serviceaccount:external-secrets:external-secrets", issuer + ":aud": "sts.amazonaws.com",
				}},
			}},
		})
	}).(pulumi.StringOutput)
	externalSecretsRole, err := iam.NewRole(ctx, name+"-external-secrets", &iam.RoleArgs{
		Name: pulumi.String(name + "-external-secrets"), AssumeRolePolicy: externalSecretsTrust, Tags: commonTags,
	}, childOptions(component, args.Provider)...)
	if err != nil {
		return nil, err
	}
	externalSecretsPolicy := pulumi.All(runtimeSecret.Arn, key.Arn).ApplyT(func(values []interface{}) (string, error) {
		return marshalJSON(map[string]any{
			"Version": "2012-10-17", "Statement": []map[string]any{
				{"Effect": "Allow", "Action": []string{"secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"}, "Resource": values[0].(string)},
				{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": values[1].(string), "Condition": map[string]any{
					"StringEquals": map[string]string{"kms:ViaService": fmt.Sprintf("secretsmanager.%s.amazonaws.com", args.Binding.Region)},
				}},
			},
		})
	}).(pulumi.StringOutput)
	if _, err = iam.NewRolePolicy(ctx, name+"-external-secrets-policy", &iam.RolePolicyArgs{
		Role: externalSecretsRole.ID(), Policy: externalSecretsPolicy,
	}, childOptions(component, args.Provider)...); err != nil {
		return nil, err
	}

	bucket, err := s3.NewBucketV2(ctx, name+"-evidence", &s3.BucketV2Args{ForceDestroy: pulumi.Bool(!protected), Tags: commonTags}, childOptions(component, args.Provider, pulumi.Protect(protected))...)
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
	component.DatabaseIdentifier = database.ClusterIdentifier
	component.RedisIdentifier = cache.ID().ToStringOutput()
	component.EvidenceBucket = bucket.Bucket
	component.KeyARN = key.Arn
	component.DatabaseEndpoint = database.Endpoint
	component.RedisEndpoint = cacheEndpoint
	component.RuntimeSecretARN = runtimeSecret.Arn
	component.Kubeconfig = cluster.KubeconfigJson
	component.ImageRepositories = repositoryURLs.ToStringMapOutput()
	component.ExternalSecretsRoleARN = externalSecretsRole.Arn
	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{
		"vpcId": component.VpcID, "clusterName": component.ClusterName, "databaseIdentifier": component.DatabaseIdentifier,
		"redisIdentifier": component.RedisIdentifier, "evidenceBucket": component.EvidenceBucket, "keyArn": component.KeyARN,
		"databaseEndpoint": component.DatabaseEndpoint, "redisEndpoint": component.RedisEndpoint,
		"runtimeSecretArn": component.RuntimeSecretARN, "kubeconfig": component.Kubeconfig,
		"imageRepositories":      component.ImageRepositories,
		"externalSecretsRoleArn": component.ExternalSecretsRoleARN,
	}); err != nil {
		return nil, err
	}
	return component, nil
}
