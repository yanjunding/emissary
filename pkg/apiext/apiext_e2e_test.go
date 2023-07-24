package apiext_test

// import (
// 	"context"
// 	"testing"

// 	crdAll "github.com/emissary-ingress/emissary/v3/pkg/api/getambassador.io"
// 	"github.com/emissary-ingress/emissary/v3/pkg/api/getambassador.io/v3alpha1"
// 	"github.com/stretchr/testify/require"
// 	k8sapiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
// 	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
// 	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
// 	"sigs.k8s.io/e2e-framework/pkg/envconf"
// 	"sigs.k8s.io/e2e-framework/pkg/features"
// )

// func TestCertWatching(t *testing.T) {
// 	feature := features.New("Cert Watching").
// 		WithSetup("", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
// 			// TODO
// 			return ctx
// 		}).
// 		Assess("Check Rotating CA Cert", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
// 			r, err := resources.New(c.Client().RESTConfig())
// 			require.NoError(t, err)

// 			r.WithNamespace(namespace)

// 			err = k8sapiextv1.AddToScheme(r.GetScheme())
// 			require.NoError(t, err)

// 			err = crdAll.AddToScheme(r.GetScheme())
// 			require.NoError(t, err)

// 			// 1. verify CABundle was correctly injected with cert
// 			mappingCRDef := &k8sapiextv1.CustomResourceDefinition{}

// 			err = r.Get(ctx, "mappings.getambassador.io", "", mappingCRDef)
// 			require.NoError(t, err)

// 			require.NotNil(t, mappingCRDef.Spec.Conversion)
// 			require.Equal(t, mappingCRDef.Spec.Conversion.Strategy, k8sapiextv1.WebhookConverter)
// 			require.NotNil(t, mappingCRDef.Spec.Conversion.Webhook)
// 			require.NotNil(t, mappingCRDef.Spec.Conversion.Webhook.ClientConfig)
// 			caBundleBytesLen := len(mappingCRDef.Spec.Conversion.Webhook.ClientConfig.CABundle)
// 			require.Greater(t, caBundleBytesLen, 0, "CA bundle bytes should be greater than 0", caBundleBytesLen)

// 			// 2. apply Mapping and verify it is successful
// 			mapping1 := &v3alpha1.Mapping{
// 				TypeMeta:   metav1.TypeMeta{Kind: "Mapping", APIVersion: "getambassador.io/v3alpha1"},
// 				ObjectMeta: metav1.ObjectMeta{Name: "mapping-1", Namespace: "default"},
// 				Spec: v3alpha1.MappingSpec{
// 					Prefix:  "/docs/",
// 					Service: "127.0.0.1:8500",
// 				},
// 			}

// 			err = r.Create(ctx, mapping1)
// 			require.NoError(t, err)

// 			err = r.Get(ctx, "mapping-1", "default", mapping1)
// 			require.NoError(t, err)

// 			// 3. create new cert and rotate it in secret

// 			// 4. verify CRD Ca bundle matches our new cert

// 			// 5. verify able to apply mapping still

// 			return ctx
// 		}).Feature()

// 	testEnv.Test(t, feature)
// }
