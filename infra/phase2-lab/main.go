package main

import (
	"fmt"

	kubernetes "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/core/v1"
	metav1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/meta/v1"
	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/networking/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

// This stack intentionally provisions only the disposable local policy shell.
// Application images and LocalStack state are supplied by the lab runner so a
// preview never hides an image pull, credential, or customer-data operation.
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
		}
		ctx.Export("cluster", pulumi.String(cluster))
		ctx.Export("localstackEndpoint", pulumi.String(cfg.Get("localstackEndpoint")))
		ctx.Export("tenants", pulumi.ToStringArray([]string{"vigil-tenant-a", "vigil-tenant-b"}))
		return nil
	})
}
