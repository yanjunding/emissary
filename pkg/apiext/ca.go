package apiext

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/datawire/dlib/dlog"
	"github.com/emissary-ingress/emissary/v3/internal/certutils"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	clientcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	listercorev1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultSubjectOrganization     = "Ambassador Labs"
	defaultNamespace               = "emissary-system"
	defaultCASecretName            = "emissary-ingress-webhook-ca"
	defaultCACertValidDuration     = 365 * 24 * time.Hour
	defaultServerCertValidDuration = 14 * 24 * time.Hour
	defaultResyncPeriod            = 10 * time.Second
)

// CertificateAuthority manages a root CA and generates Server certs
// for an https Server.
type CertificateAuthority interface {
	// Start will kick off async processes and block until shutdown or error occurs
	Start(context.Context) error
	// GetCertificates matches `crypto/tls` to provide a valid server cert for listening to incoming connections
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// IsStarted will return true once the POD has ensured a CA/CRD Bundle and Server cert is available
	IsStarted() bool
	// IsHealthy provides a healthz indication by ensuring the server cert is available and valid
	IsHealthy() bool
}

// CAConfigOption allows overriding the default config options for `APIExtCertificateAuthority`
type CAConfigOption func(*APIExtCertificateAuthority)

// WithCASecretNamespace overrides the default namespace where the CA Cert Secret will be stored and watched
func WithCASecretNamespace(namespace string) CAConfigOption {
	return func(m *APIExtCertificateAuthority) {
		m.caSecretNamespace = namespace
	}
}

// WithCASecretName overrides the default name used to store the CA Cert in a Secret.
func WithCASecretName(secretName string) CAConfigOption {
	return func(m *APIExtCertificateAuthority) {
		m.caSecretName = secretName
	}
}

// WithRestConfig provides k8s config to use for communicating with a k8s cluster.
func WithRestConfig(restConfig *rest.Config) CAConfigOption {
	return func(m *APIExtCertificateAuthority) {
		m.restConfig = restConfig
	}
}

// WithLogger allows provide a custom logger instance
func WithLogger(logger dlog.Logger) CAConfigOption {
	return func(m *APIExtCertificateAuthority) {
		m.logger = logger
	}
}

// APIExtCertificateAuthority is an implementation of the interface `CertificateAuthority` which manages
// the root CA cert, server cert and ensuring the CRD CA Bundle is setup properly.
type APIExtCertificateAuthority struct {
	ctx    context.Context
	logger dlog.Logger

	secretLister      listercorev1.SecretNamespaceLister
	secretClient      clientcorev1.SecretInterface
	restConfig        *rest.Config
	caSecretNamespace string
	caSecretName      string

	caCert       *x509.Certificate
	caPrivateKey *rsa.PrivateKey
	caMu         sync.RWMutex

	certCache   map[string]*tls.Certificate
	certCacheMu sync.RWMutex

	initialized bool
}

var _ CertificateAuthority = (*APIExtCertificateAuthority)(nil)

// NewAPIExtCertificateAuthority will initialize a new instance of the APIExtCertificateAuthority.
func NewAPIExtCertificateAuthority(options ...CAConfigOption) (*APIExtCertificateAuthority, error) {
	manager := &APIExtCertificateAuthority{
		caSecretNamespace: defaultNamespace,
		caSecretName:      defaultCASecretName,
	}

	for _, optFn := range options {
		optFn(manager)
	}

	if manager.restConfig == nil {
		restConfig, err := rest.InClusterConfig()
		if err != nil {
			panic(err)
		}

		manager.restConfig = restConfig
	}

	return manager, nil
}

// GetCertificate implements CertificateAuthority.
func (ca *APIExtCertificateAuthority) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return ca.genServerCert(context.Background(), clientHello.ServerName)
}

// IsStarted will provide indication that the startup phase is over and can be used with Startup Probes
func (ca *APIExtCertificateAuthority) IsStarted() bool {
	return ca.initialized
}

// IsHealthy ensures that a serverCert is available and the startup has completed
func (ca *APIExtCertificateAuthority) IsHealthy() bool {
	ca.certCacheMu.RLock()
	defer ca.certCacheMu.RUnlock()

	return ca.initialized && ca.certCache != nil
}

// Start instructs the CertifcateAuthority to start managing the CA Root and server certificate
// It will ensure the K8s Secret, in-memory Root CA Cert and server cert are kept in-sync
func (ca *APIExtCertificateAuthority) Start(ctx context.Context) error {
	ca.ctx = ctx

	clientset, err := kubernetes.NewForConfig(ca.restConfig)
	if err != nil {
		return err
	}

	ca.secretClient = clientset.CoreV1().Secrets(ca.caSecretNamespace)

	informerFactory := informers.NewSharedInformerFactoryWithOptions(clientset,
		defaultResyncPeriod,
		informers.WithNamespace(ca.caSecretNamespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = "metadata.name=" + ca.caSecretName
		}),
	)
	defer informerFactory.Shutdown()

	ca.secretLister = informerFactory.Core().V1().Secrets().Lister().Secrets(ca.caSecretNamespace)

	secretInformer := informerFactory.Core().V1().Secrets().Informer()
	_, err = secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ca.handleCASecretAdd,
		UpdateFunc: ca.handleCASecretUpdate,
		DeleteFunc: ca.handleCASecretDelete,
	})
	if err != nil {
		return fmt.Errorf("failed to setup watches on secrets, %w", err)
	}

	informerFactory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), secretInformer.HasSynced) {
		return fmt.Errorf("failed to sync CA Secret cache")
	}

	// block until we receive a shutdown signal from ctx
	<-ctx.Done()

	return nil
}

// fullSecretName returns the fully qualified namespace/name for the ca secret to simplify logging
func (ca *APIExtCertificateAuthority) fullSecretName() string {
	return fmt.Sprintf("%s/%s", ca.caSecretNamespace, ca.caSecretName)
}

// handleCASecretDelete is triggered when the secret informer sees a 'add' event on the CA Secret
func (ca *APIExtCertificateAuthority) handleCASecretAdd(secretObj interface{}) {
	ctx := context.Background()
	if err := ca.ensureCA(ctx); err != nil {
		dlog.Errorf(ctx, "secret added: error occurred ensuring valid ca cert, %s", err)
	}

}

// handleCASecretDelete is triggered when the secret informer sees a 'update' event on the CA Secret
func (ca *APIExtCertificateAuthority) handleCASecretUpdate(oldSecretObj interface{}, newSecretObj interface{}) {
	ctx := context.Background()
	if err := ca.ensureCA(ctx); err != nil {
		dlog.Errorf(ctx, "secret updated: error occurred ensuring valid ca cert, %s", err)
	}

}

// handleCASecretDelete is triggered when the secret informer sees a 'delete' event on the CA Secret
func (ca *APIExtCertificateAuthority) handleCASecretDelete(secretObj interface{}) {
	ctx := context.Background()
	if err := ca.ensureCA(ctx); err != nil {
		dlog.Errorf(ctx, "secret deleted: error occurred ensuring valid ca cert, %s", err)
	}

}

// ensureCA  ensures that a CA Cert is valid and available for generating Server certs
func (ca *APIExtCertificateAuthority) ensureCA(ctx context.Context) error {
	// grabbing the lock here to ensure that calls to this function happen in
	// synchronous order and the informer will wait before catching next event
	ca.caMu.Lock()
	defer ca.caMu.Unlock()

	secret, err := ca.secretClient.Get(ctx, ca.caSecretName, metav1.GetOptions{})
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			dlog.Infof(ctx, "ca secret %q not found, generating new root CA", ca.fullSecretName())
			return ca.generateCACert(ctx, nil)
		}

		dlog.Errorf(ctx, "unable to fetch %q: %s", ca.fullSecretName(), err.Error())
		return err
	}

	if ca.isCASecretInvalid(secret) {
		return ca.generateCACert(ctx, secret.DeepCopy())
	}

	return nil
}

func (ca *APIExtCertificateAuthority) generateCACert(ctx context.Context, secret *corev1.Secret) error {
	dlog.Infof(ctx, "generating a new root ca cert for %q", ca.fullSecretName())

	privateKey, cert, err := certutils.GenerateRootCACert(defaultSubjectOrganization, defaultCACertValidDuration)
	if err != nil {
		return err
	}

	secretData := map[string][]byte{
		corev1.TLSPrivateKeyKey: privateKey,
		corev1.TLSCertKey:       cert,
	}

	if secret == nil {
		_, err := ca.secretClient.Create(ctx,
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ca.caSecretName,
					Namespace: ca.caSecretNamespace,
				},
				Type: corev1.SecretTypeTLS,
				Data: secretData,
			}, metav1.CreateOptions{})
		return err
	}

	secret.Data = secretData
	_, err = ca.secretClient.Update(ctx, secret, metav1.UpdateOptions{})

	return err
}

// isCASecretInvalid determines if the CA cert within the secret is invalid. This will indicate
// whether a new CA Cert needs to be generated.
func (ca *APIExtCertificateAuthority) isCASecretInvalid(secret *corev1.Secret) bool {
	ctx := context.Background()

	if secret == nil || secret.Data == nil {
		return true
	}

	caPrivateKeyPEMBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		dlog.Infof(ctx, "no %s found in ca secret %s", corev1.TLSPrivateKeyKey, ca.fullSecretName())
		return true
	}

	caKeyBlock, _ := pem.Decode(caPrivateKeyPEMBytes)
	_caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		dlog.Errorf(ctx, "unable to parse %s found in ca secret %s, %s", corev1.TLSPrivateKeyKey, ca.fullSecretName(), err)
		return true
	}

	caPrivateKey, ok := _caKey.(*rsa.PrivateKey)
	if !ok {
		dlog.Infof(ctx, "%s found in ca secret %s is not a valid RSA key", corev1.TLSPrivateKeyKey, ca.fullSecretName())
		return true
	}

	// cert
	caCertPEMBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		dlog.Infof(ctx, "no %s found in ca secret %s", corev1.TLSCertKey, ca.fullSecretName())
		return true
	}

	caCertBlock, _ := pem.Decode(caCertPEMBytes)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		dlog.Errorf(ctx, "unable to parse %s found in ca secret %s, %s", corev1.TLSCertKey, ca.fullSecretName(), err)
		return true
	}

	if !caCert.IsCA {
		dlog.Infof(ctx, "%s found in ca secret %s is not marked as a CA", corev1.TLSCertKey, ca.fullSecretName())
		return true
	}

	// automatically force re-generating when 1 month until expires
	if caCert.NotAfter.Sub(time.Now()) < (defaultCACertValidDuration / 12) {
		dlog.Info(ctx, "root ca certificate is expiring soon, forcing ca cert generation")
		return true
	}

	// Note: the lock for these fields have already been grabbed, see ensureCA.
	ca.caPrivateKey = caPrivateKey
	ca.caCert = caCert
	ca.resetCertCache()
	ca.initialized = true

	return false
}

// resetCertCache clears out all the server certs so that they can be regenerated
// this should be called anytime the CA cert has been modified.
func (ca *APIExtCertificateAuthority) resetCertCache() {
	ca.certCacheMu.Lock()
	ca.certCache = make(map[string]*tls.Certificate)
	ca.certCacheMu.Unlock()
}

// genServerCert will provide hostname a server cert from the cache or will
// generate a new one using the CA Certificate
func (ca *APIExtCertificateAuthority) genServerCert(ctx context.Context, hostname string) (*tls.Certificate, error) {
	ca.certCacheMu.Lock()
	defer ca.certCacheMu.Unlock()

	if ca.certCache == nil {
		ca.certCache = make(map[string]*tls.Certificate)
	}

	now := time.Now()

	if cachedCert, ok := ca.certCache[hostname]; ok && cachedCert != nil && cachedCert.Leaf != nil {
		age := now.Sub(cachedCert.Leaf.NotBefore)
		lifespan := cachedCert.Leaf.NotAfter.Sub(cachedCert.Leaf.NotBefore)
		if age < 2*lifespan/3 {
			dlog.Debugf(ctx, "using cached server cert for hostname=%s with age=%v and lifespan=%v", hostname, age, lifespan)
			return cachedCert, nil
		}

		dlog.Debugf(ctx, "cache server cert for hostname=%s is too old (age=%v lifespan=%v)", hostname, age, lifespan)
	}

	dlog.Infof(ctx, "generating new server cert for hostname=%s", hostname)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{defaultSubjectOrganization},
			CommonName:   "Webhook API",
		},
		NotBefore:             now,
		NotAfter:              now.Add(defaultServerCertValidDuration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	ca.caMu.RLock()
	caCert := ca.caCert
	caKey := ca.caPrivateKey
	ca.caMu.Unlock()

	certPEMBytes, err := x509.CreateCertificate(
		rand.Reader,
		cert,
		caCert,
		priv.Public(),
		caKey,
	)

	if err != nil {
		return nil, err
	}

	serverCert := &tls.Certificate{
		Certificate: [][]byte{certPEMBytes},
		PrivateKey:  priv,
		Leaf:        cert,
	}

	ca.certCache[hostname] = serverCert
	return serverCert, nil
}
