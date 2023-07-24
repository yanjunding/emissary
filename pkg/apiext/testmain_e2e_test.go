package apiext_test

// import (
// 	"os"
// 	"testing"
// 	"time"

// 	"github.com/emissary-ingress/emissary/v3/internal/e2eutils"
// 	"sigs.k8s.io/e2e-framework/klient/conf"
// 	"sigs.k8s.io/e2e-framework/pkg/env"
// 	"sigs.k8s.io/e2e-framework/pkg/envconf"
// 	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
// )

// var (
// 	testEnv     env.Environment
// 	clusterName string
// 	namespace   string
// )

// func TestMain(m *testing.M) {
// 	testEnv = env.New()

// 	crdPath := "../../build-output/apiext-e2e"
// 	crdPattern := "*"
// 	namespace = "emissary-system"

// 	// Bring-your-own-cluster for faster local devloop and/or CI runs
// 	if _, ok := os.LookupEnv("BYO_CLUSTER"); ok {
// 		kubeConfigPath := conf.ResolveKubeConfigFile()
// 		cfg := envconf.NewWithKubeConfig(kubeConfigPath)
// 		testEnv = env.NewWithConfig(cfg)

// 		testEnv.Setup(
// 			envfuncs.SetupCRDs(crdPath, crdPattern),
// 			e2eutils.WaitForAPIExt(kubeConfigPath, 30*time.Second),
// 		)

// 		testEnv.Finish(
// 			envfuncs.TeardownCRDs(crdPath, crdPattern),
// 		)
// 	} else {
// 		cfg, _ := envconf.NewFromFlags()
// 		testEnv = env.NewWithConfig(cfg)
// 		clusterName = envconf.RandomName("apiext-e2e", 16)
// 		kubeConfigPath, _ := e2eutils.GetK3dClusterConfigPath(clusterName)

// 		k3sVersion := "v1.25.7-k3s1"
// 		if version, ok := os.LookupEnv("K3S_VERSION"); ok {
// 			k3sVersion = version
// 		}

// 		testEnv.Setup(
// 			e2eutils.CreateK3dCluster(clusterName, k3sVersion),
// 			envfuncs.SetupCRDs(crdPath, crdPattern),
// 			e2eutils.WaitForAPIExt(kubeConfigPath, 30*time.Second),
// 		)

// 		testEnv.Finish(
// 			e2eutils.DestroyK3dCluster(clusterName),
// 			envfuncs.TeardownCRDs(crdPath, crdPattern),
// 		)
// 	}

// 	os.Exit(testEnv.Run(m))
// }
