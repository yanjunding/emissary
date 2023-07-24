package apiext

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/datawire/dlib/dgroup"
	"github.com/datawire/dlib/dhttp"
	"github.com/datawire/dlib/dlog"
	"github.com/emissary-ingress/emissary/v3/pkg/busy"
	"github.com/emissary-ingress/emissary/v3/pkg/k8s"
	"github.com/emissary-ingress/emissary/v3/pkg/logutil"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/conversion"
)

const (
	pathWebhooksCrdConvert = "/webhooks/crd-convert"
	pathProbesReady        = "/probes/ready"
	pathProbesLive         = "/probes/live"
)

// podNamespace determines the current Pods namespace
//
// Logic is borrowed from "k8s.io/client-go/tools/clientcmd".inClusterConfig.Namespace()
func podNamespace() string {
	// This way assumes you've set the POD_NAMESPACE environment variable using the downward API.
	// This check has to be done first for backwards compatibility with the way InClusterConfig was originally set up
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}

	// Fall back to the namespace associated with the service account token, if available
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}

	return "default"
}

// Webhook provides a simple abstraction for apiext webhook server
type WebhookRunner interface {
	Run(ctx context.Context, resourceScheme *runtime.Scheme) error
}

// WebhookServerConfig provides settings to configure the WebhookServer at runtime.
type WebhookServerConfig struct {
	Namespace   string
	ServiceName string
	HTTPPort    int
	HTTPSPort   int
	CAManager   CertificateAuthority
}

type WebhookServer struct {
	namespace   string
	serviceName string
	httpPort    int
	httpsPort   int
	caManager   CertificateAuthority
}

func NewWebhookServer(config WebhookServerConfig) *WebhookServer {
	server := &WebhookServer{
		namespace:   config.Namespace,
		serviceName: config.ServiceName,
		httpPort:    config.HTTPPort,
		httpsPort:   config.HTTPSPort,
		caManager:   config.CAManager,
	}

	if server.namespace == "" {
		server.namespace = podNamespace()
	}

	if server.httpPort == 0 {
		server.httpPort = 8080
	}

	if server.httpsPort == 0 {
		server.httpsPort = 8443
	}

	if server.serviceName == "" {
		server.serviceName = "emissary-apiext"
	}

	return server
}

// Run the Emissary-ingress apiext conversion webhook using the provided configuration
func (s *WebhookServer) Run(ctx context.Context, scheme *runtime.Scheme) error {
	if lvl, err := logutil.ParseLogLevel(os.Getenv("APIEXT_LOGLEVEL")); err == nil {
		busy.SetLogLevel(lvl)
	}
	dlog.Infof(ctx, "APIEXT_LOGLEVEL=%v", busy.GetLogLevel())

	kubeinfo := k8s.NewKubeInfo("", "", "")
	restConfig, err := kubeinfo.GetRestConfig()
	if err != nil {
		return err
	}

	if s.caManager == nil {
		s.caManager, err = NewAPIExtCertificateAuthority(
			WithRestConfig(restConfig),
		)
		if err != nil {
			return err
		}
	}

	grp := dgroup.NewGroup(ctx, dgroup.GroupConfig{
		EnableSignalHandling: true,
	})

	grp.Go("ca-manager", func(ctx context.Context) error {
		return s.caManager.Start(ctx)
	})

	// TODO - create CRD Injector
	// grp.Go("configure-crds", func(ctx context.Context) error {
	// 	return apiext.ConfigureCRDs(ctx,
	// 		restConfig,
	// 		s.serviceName,
	// 		s.namespace,
	// 		caSecret,
	// 		scheme)
	// })

	grp.Go("serve-healthz", func(ctx context.Context) error {
		return s.serveHealthz(ctx)
	})

	grp.Go("serve-https", func(ctx context.Context) error {
		return s.serveHTTPS(ctx, scheme)
	})

	return grp.Wait()
}

// serveHTTPS starts listening for incoming https request and handles ConversionWebhookRequuests.
func (s *WebhookServer) serveHTTPS(ctx context.Context, scheme *runtime.Scheme) error {
	dlog.Infof(ctx, "serving https on port %d", s.httpsPort)

	webhookHandler := conversion.NewWebhookHandler(scheme)

	mux := http.NewServeMux()
	mux.Handle(pathWebhooksCrdConvert, webhookHandler)

	sc := &dhttp.ServerConfig{
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: s.caManager.GetCertificate,
		},
	}

	if logLevelIsAtLeastDebug() {
		sc.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conversionWithLogging(webhookHandler, w, r)
		})
	}

	return sc.ListenAndServeTLS(ctx, fmt.Sprintf(":%d", s.httpsPort), "", "")
}

// serveHealthz starts http server listening for http healthz (ready,liviness)
func (s *WebhookServer) serveHealthz(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.Handle(pathProbesReady, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if s.caManager.IsStarted() && s.caManager.IsHealthy() {
			_, _ = io.WriteString(w, "Ready!\n")
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		return
	}))

	mux.Handle(pathProbesLive, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "Living!\n")
	}))

	sc := &dhttp.ServerConfig{
		Handler: mux,
	}
	return sc.ListenAndServe(ctx, fmt.Sprintf(":%d", s.httpPort))
}

// conversionWithLogging is a wrapper around our real conversion method that logs the JSON
// input and output for the conversion request. It's used only when we have debug logging
// enabled.
func conversionWithLogging(handler http.Handler, w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		dlog.Errorf(r.Context(), "no conversion request provided")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	inputBytes, err := ioutil.ReadAll(r.Body)

	// This is mirrored from wh.ServeHttp (cf sigs.k8s.io/controller-runtime/pkg/webhook/conversion.go).
	if err != nil {
		dlog.Errorf(r.Context(), "could not read conversion request: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	dlog.Debugf(r.Context(), "INPUT: %s", string(inputBytes))

	r.Body = io.NopCloser(bytes.NewBuffer(inputBytes))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	dlog.Debugf(r.Context(), "OUTPUT: %s", rec.Body)

	for k, v := range rec.Result().Header {
		w.Header()[k] = v
	}

	w.WriteHeader(rec.Code)

	// ignore errors if we can't write back, k8s-api server will error on bad response
	_, _ = rec.Body.WriteTo(w)
}

// logLevelIsAtLeastDebug checks the current log level to determine next steps
func logLevelIsAtLeastDebug() bool {
	return busy.GetLogLevel() >= logrus.DebugLevel
}
