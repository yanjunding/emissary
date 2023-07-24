package apiext

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/datawire/dlib/dlog"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8sSchema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	requeueAfterDefault = 10 * time.Second
)

// crdController handle reconiliation for CRD's to ensure the CACert bundle is injected correctly
type crdController struct {
	client.Client

	serviceName      string
	serviceNamespace string

	caSecretName      string
	caSecretNamespace string
}

func newCRDController(client client.Client) *crdController {
	caSecretName := "something"
	caSecretNamespace := "emissary-system"

	return &crdController{
		Client:            client,
		caSecretName:      caSecretName,
		caSecretNamespace: caSecretNamespace,
	}
}

// SetupWithManager will register indexes, watches and registers the controller to reconcile CRD.
func (c *crdController) SetupWithManager(mgr manager.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&apiextv1.CustomResourceDefinition{}).
		Watches(
			&corev1.Secret{},
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(
				predicate.NewPredicateFuncs(caSecretPredicate(c.caSecretName, c.caSecretNamespace)),
			),
		).
		Complete(c)
}

// Reconcile implements reconcile.Reconciler.
func (c *crdController) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	dlog.Info(ctx, "reconcile loop has occurred")

	// Make sure we have a valid CA Bundle before trying to update some stuff
	cabundle, err := c.fetchCABundle(ctx)
	if err != nil {
		return reconcile.Result{RequeueAfter: requeueAfterDefault}, err
	}

	// get all CRDS
	crds := &apiextv1.CustomResourceDefinitionList{}
	if err := c.List(ctx, crds); err != nil {
		return reconcile.Result{RequeueAfter: requeueAfterDefault},
			fmt.Errorf("error listing CustomerResourceDefinitions: %w", err)
	}

	errorCount := 0

	for _, crDef := range crds.Items {
		err := c.reconcileCustomResourceDefintion(ctx, &crDef, cabundle)
		if err != nil {
			errorCount++
			dlog.Errorf(ctx, "error occured trying to inject ca bundle into %s/%s, %s", c.caSecretNamespace, c.caSecretName, err)
		}
	}

	if errorCount > 0 {
		return reconcile.Result{RequeueAfter: requeueAfterDefault},
			fmt.Errorf("an error occured injecting CA Bundle into CRD's")
	}

	return reconcile.Result{}, nil
}

// fetchCABundle will grab the ca bundle from the configured CA secret
func (c *crdController) fetchCABundle(ctx context.Context) ([]byte, error) {
	caSecret := &corev1.Secret{}

	if err := c.Get(ctx, types.NamespacedName{Namespace: c.caSecretNamespace, Name: c.caSecretName}, caSecret); err != nil {
		return nil, fmt.Errorf("error getting ca secret %s/%s: %w", c.caSecretNamespace, c.caSecretName, err)
	}

	if caSecret == nil || caSecret.Data == nil {
		return nil, fmt.Errorf("invalid secret, missing Data in %s/%s", c.caSecretNamespace, c.caSecretName)
	}

	caBytes, ok := caSecret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("missing ca cert, %s key not found in the %s/%s", corev1.TLSCertKey, c.caSecretNamespace, c.caSecretName)
	}

	return caBytes, nil
}

// reconcileCustomResourceDefinition will patch the CA Bundle if needed.
func (c *crdController) reconcileCustomResourceDefintion(ctx context.Context, crDef *apiextv1.CustomResourceDefinition, caBundle []byte) error {
	if !c.Scheme().Recognizes(k8sSchema.GroupVersionKind{
		Group:   crDef.Spec.Group,
		Version: crDef.Spec.Versions[0].Name,
		Kind:    crDef.Spec.Names.Kind,
	}) {
		// skipping definition because we don't recognize scheme and cannot inject it
		dlog.Debugf(ctx, "skipping %q because it is not a recognized api group", crDef.ObjectMeta.Name)
		return nil
	}

	if len(crDef.Spec.Versions) < 2 {
		dlog.Debugf(ctx, "skipping %q because it only has one version and doesn't need converted", crDef.ObjectMeta.Name)
		return nil
	}

	conversionConfig := c.createConversionConfig(caBundle)
	if reflect.DeepEqual(crDef.Spec.Conversion, conversionConfig) {
		// Already done.
		dlog.Infof(ctx, "skipping %q because it is already configured", crDef.ObjectMeta.Name)
		return nil
	}

	crDef.Spec.Conversion = conversionConfig
	return c.Update(ctx, crDef)
}

func (c *crdController) createConversionConfig(caBundle []byte) *apiextv1.CustomResourceConversion {

	webhookPath := pathWebhooksCrdConvert // because pathWebhooksCrdConvert is a 'const' and you can't take the address of a const
	webhookPort := int32(443)
	conversionConfig := &apiextv1.CustomResourceConversion{
		Strategy: apiextv1.WebhookConverter,
		Webhook: &apiextv1.WebhookConversion{
			ClientConfig: &apiextv1.WebhookClientConfig{
				Service: &apiextv1.ServiceReference{
					Name:      c.serviceName,
					Namespace: c.serviceNamespace,
					Port:      &webhookPort,
					Path:      &webhookPath,
				},
				CABundle: caBundle,
			},
			ConversionReviewVersions: []string{"v1"},
		},
	}

	return conversionConfig
}
