package apiext

import (
	"context"

	"github.com/datawire/dlib/dgroup"
)

// CRDPatcher watches CRD's in a cluster and can patch them
type CRDPatcher interface {
	Start(context.Context) error
}

// ConversionWebhookCAInjector will watch for CRD changes and CA Cert changes and will patch the
// ConversionWebhook with the correct CA bundle
type ConversionWebhookCAInjector struct {
}

// This will need to watch the Secret and will also watch for changes in CRD's

// Watch will watch for CRDs that are Added or Updated
func (ci *ConversionWebhookCAInjector) Start(ctx context.Context) error {

	crdController := newCRDController(nil)
	crdController.SetupWithManager(mgr)

	grp := dgroup.NewGroup(ctx, dgroup.GroupConfig{
		EnableSignalHandling: true,
	})

	// TODO: instantiate instance of controller and get it running

	return grp.Wait()
}
