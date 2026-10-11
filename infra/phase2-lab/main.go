package main

import (
	"fmt"

	kubernetes "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
	appsv1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/apps/v1"
	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/core/v1"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/networking/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func labels(tenant, target string) pulumi.StringMap {
	return pulumi.StringMap{
		"vigil.io/tenant":               pulumi.String(tenant),
		"vigil.io/qualification-target": pulumi.String(target),
	}
}

func service(
	ctx *pulumi.Context,
	provider *kubernetes.Provider,
	ns *corev1.Namespace,
	name string,
	selector pulumi.StringMap,
	port int,
) (*corev1.Service, error) {
	return corev1.NewService(ctx, name, &corev1.ServiceArgs{
		Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String(name), Namespace: ns.Metadata.Name()},
		Spec: &corev1.ServiceSpecArgs{
			Selector: selector,
			Ports: corev1.ServicePortArray{&corev1.ServicePortArgs{
				Name: pulumi.String("http"), Port: pulumi.Int(port), TargetPort: pulumi.Int(port),
			}},
		},
	}, pulumi.Provider(provider))
}

func allowTarget(
	ctx *pulumi.Context,
	provider *kubernetes.Provider,
	ns *corev1.Namespace,
	name, tenant, sourceComponent, target string,
	port int,
) error {
	targetLabels := labels(tenant, target)
	_, err := v1.NewNetworkPolicy(ctx, name+"-ingress", &v1.NetworkPolicyArgs{
		Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String(name), Namespace: ns.Metadata.Name()},
		Spec: &v1.NetworkPolicySpecArgs{
			PodSelector: &metav1.LabelSelectorArgs{MatchLabels: targetLabels},
			PolicyTypes: pulumi.StringArray{pulumi.String("Ingress")},
			Ingress: v1.NetworkPolicyIngressRuleArray{&v1.NetworkPolicyIngressRuleArgs{
				From: v1.NetworkPolicyPeerArray{&v1.NetworkPolicyPeerArgs{
					PodSelector: &metav1.LabelSelectorArgs{MatchLabels: pulumi.StringMap{
						"app.kubernetes.io/component": pulumi.String(sourceComponent),
					}},
				}},
				Ports: v1.NetworkPolicyPortArray{&v1.NetworkPolicyPortArgs{Port: pulumi.Int(port)}},
			}},
		},
	}, pulumi.Provider(provider))
	if err != nil {
		return err
	}
	_, err = v1.NewNetworkPolicy(ctx, name+"-egress", &v1.NetworkPolicyArgs{
		Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String(name + "-egress"), Namespace: ns.Metadata.Name()},
		Spec: &v1.NetworkPolicySpecArgs{
			PodSelector: &metav1.LabelSelectorArgs{MatchLabels: pulumi.StringMap{
				"app.kubernetes.io/component": pulumi.String(sourceComponent),
			}},
			PolicyTypes: pulumi.StringArray{pulumi.String("Egress")},
			Egress: v1.NetworkPolicyEgressRuleArray{&v1.NetworkPolicyEgressRuleArgs{
				To: v1.NetworkPolicyPeerArray{&v1.NetworkPolicyPeerArgs{
					PodSelector: &metav1.LabelSelectorArgs{MatchLabels: targetLabels},
				}},
				Ports: v1.NetworkPolicyPortArray{&v1.NetworkPolicyPortArgs{Port: pulumi.Int(port)}},
			}},
		},
	}, pulumi.Provider(provider))
	return err
}

// This stack provisions only disposable qualification infrastructure. Product
// services remain Helm releases; the targets below give their network policies
// real, ready cloud/model destinations to allow or deny.
func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		cfg := config.New(ctx, "vigil-phase2-lab")
		cluster := cfg.Get("cluster")
		if cluster == "" {
			cluster = "vigil-phase2"
		}
		kubeContext := cfg.Require("kubeContext")
		kubeconfig := cfg.RequireSecret("kubeconfig")
		provider, err := kubernetes.NewProvider(ctx, "phase2-kube", &kubernetes.ProviderArgs{
			Kubeconfig: kubeconfig,
			Context:    pulumi.String(kubeContext),
		})
		if err != nil {
			return err
		}
		for _, tenant := range []string{"a", "b"} {
			nsName := fmt.Sprintf("vigil-tenant-%s", tenant)
			ns, err := corev1.NewNamespace(ctx, nsName, &corev1.NamespaceArgs{
				Metadata: &metav1.ObjectMetaArgs{
					Name:   pulumi.String(nsName),
					Labels: pulumi.StringMap{"vigil.io/tenant": pulumi.String(tenant), "vigil.io/lab": pulumi.String("phase2")},
				},
			}, pulumi.Provider(provider))
			if err != nil {
				return err
			}
			// Egress is deny-by-default. Tenant manifests add only the queue,
			// security service, reasoner, and connector peers required by the test.
			_, err = v1.NewNetworkPolicy(ctx, nsName+"-deny-egress", &v1.NetworkPolicyArgs{
				Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String(nsName + "-deny-egress"), Namespace: ns.Metadata.Name()},
				Spec: &v1.NetworkPolicySpecArgs{
					PodSelector: &metav1.LabelSelectorArgs{MatchLabels: pulumi.StringMap{"vigil.io/tenant": pulumi.String(tenant)}},
					PolicyTypes: pulumi.StringArray{pulumi.String("Egress")},
					Egress:      v1.NetworkPolicyEgressRuleArray{},
				},
			}, pulumi.Provider(provider))
			if err != nil {
				return err
			}

			localstackLabels := labels(tenant, "localstack")
			_, err = appsv1.NewDeployment(ctx, nsName+"-localstack", &appsv1.DeploymentArgs{
				Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String("phase2-localstack"), Namespace: ns.Metadata.Name()},
				Spec: &appsv1.DeploymentSpecArgs{
					Replicas: pulumi.Int(1),
					Selector: &metav1.LabelSelectorArgs{MatchLabels: localstackLabels},
					Template: &corev1.PodTemplateSpecArgs{
						Metadata: &metav1.ObjectMetaArgs{Labels: localstackLabels},
						Spec: &corev1.PodSpecArgs{
							AutomountServiceAccountToken: pulumi.Bool(false),
							Containers: corev1.ContainerArray{&corev1.ContainerArgs{
								Name: pulumi.String("localstack"), Image: pulumi.String("localstack/localstack:4.8.1"),
								Ports: corev1.ContainerPortArray{&corev1.ContainerPortArgs{ContainerPort: pulumi.Int(4566)}},
								ReadinessProbe: &corev1.ProbeArgs{
									InitialDelaySeconds: pulumi.Int(5), PeriodSeconds: pulumi.Int(2), FailureThreshold: pulumi.Int(90),
									HttpGet: &corev1.HTTPGetActionArgs{Path: pulumi.String("/_localstack/health"), Port: pulumi.Int(4566)},
								},
								Env: corev1.EnvVarArray{
									&corev1.EnvVarArgs{Name: pulumi.String("SERVICES"), Value: pulumi.String("s3,secretsmanager")},
									&corev1.EnvVarArgs{Name: pulumi.String("DEFAULT_REGION"), Value: pulumi.String("us-east-1")},
									&corev1.EnvVarArgs{Name: pulumi.String("EAGER_SERVICE_LOADING"), Value: pulumi.String("1")},
								},
							}},
						},
					},
				},
			}, pulumi.Provider(provider))
			if err != nil {
				return err
			}
			if _, err = service(ctx, provider, ns, nsName+"-localstack-service", localstackLabels, 4566); err != nil {
				return err
			}

			modelLabels := labels(tenant, "model-proxy")
			_, err = appsv1.NewDeployment(ctx, nsName+"-model-proxy", &appsv1.DeploymentArgs{
				Metadata: &metav1.ObjectMetaArgs{Name: pulumi.String("phase2-model-proxy"), Namespace: ns.Metadata.Name()},
				Spec: &appsv1.DeploymentSpecArgs{
					Replicas: pulumi.Int(1),
					Selector: &metav1.LabelSelectorArgs{MatchLabels: modelLabels},
					Template: &corev1.PodTemplateSpecArgs{
						Metadata: &metav1.ObjectMetaArgs{Labels: modelLabels},
						Spec: &corev1.PodSpecArgs{
							AutomountServiceAccountToken: pulumi.Bool(false),
							Containers: corev1.ContainerArray{&corev1.ContainerArgs{
								Name: pulumi.String("model-proxy"), Image: pulumi.String("busybox:1.37.0"),
								Command: pulumi.StringArray{pulumi.String("/bin/sh"), pulumi.String("-ec")},
								Args:    pulumi.StringArray{pulumi.String("mkdir -p /tmp/www; echo ready >/tmp/www/health; exec httpd -f -p 8446 -h /tmp/www")},
								Ports:   corev1.ContainerPortArray{&corev1.ContainerPortArgs{ContainerPort: pulumi.Int(8446)}},
								SecurityContext: &corev1.SecurityContextArgs{
									AllowPrivilegeEscalation: pulumi.Bool(false), ReadOnlyRootFilesystem: pulumi.Bool(true),
									RunAsNonRoot: pulumi.Bool(true), RunAsUser: pulumi.Int(65534), RunAsGroup: pulumi.Int(65534),
								},
								VolumeMounts: corev1.VolumeMountArray{&corev1.VolumeMountArgs{
									Name: pulumi.String("www"), MountPath: pulumi.String("/tmp/www"),
								}},
							}},
							Volumes: corev1.VolumeArray{&corev1.VolumeArgs{
								Name: pulumi.String("www"), EmptyDir: &corev1.EmptyDirVolumeSourceArgs{},
							}},
						},
					},
				},
			}, pulumi.Provider(provider))
			if err != nil {
				return err
			}
			if _, err = service(ctx, provider, ns, nsName+"-model-service", modelLabels, 8446); err != nil {
				return err
			}
			if err = allowTarget(ctx, provider, ns, nsName+"-allow-connector-localstack", tenant, "connector", "localstack", 4566); err != nil {
				return err
			}
			if err = allowTarget(ctx, provider, ns, nsName+"-allow-reasoner-model", tenant, "reasoner", "model-proxy", 8446); err != nil {
				return err
			}
		}
		ctx.Export("cluster", pulumi.String(cluster))
		ctx.Export("localstackEndpoints", pulumi.ToStringMap(map[string]string{
			"tenant-a": "http://vigil-tenant-a-localstack-service.vigil-tenant-a.svc.cluster.local:4566",
			"tenant-b": "http://vigil-tenant-b-localstack-service.vigil-tenant-b.svc.cluster.local:4566",
		}))
		ctx.Export("tenants", pulumi.ToStringArray([]string{"vigil-tenant-a", "vigil-tenant-b"}))
		return nil
	})
}
