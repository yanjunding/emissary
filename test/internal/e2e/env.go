package e2e

import (
	"os"
	"time"

	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
)

// TestEnvironmentConfig provides basic configuration that can be used when generation a new
// E2E test environment.
type TestEnvironmentConfig struct {
	CRDConfigLocation string
	CRDConfigPattern  string

	// ClusterNamePrefix along with a random generated string are used to create a unique
	// cluster name for the test. If not supplied it defaults to "e2etest".
	ClusterNamePrefix string
}

// TestEnvironment contains the instance of the environment and config used to create it
type TestEnvironment struct {
	Environment env.Environment
	Config      *envconf.Config
}

// NewTestEnvironment generates a new e2e testing environment based on the provided configuration.
//
// It currently supports bringing your own cluster or will generate a local k3d cluster
// that can be used for running e2e tests.
func NewTestEnvironment(testEnvConfig *TestEnvironmentConfig) *TestEnvironment {
	testEnv := env.New()
	var cfg *envconf.Config

	// Bring-your-own-cluster for faster iteration when debugging tests locally
	if _, ok := os.LookupEnv("BYO_CLUSTER"); ok {
		kubeConfigPath := conf.ResolveKubeConfigFile()
		cfg = envconf.NewWithKubeConfig(kubeConfigPath)
		testEnv = env.NewWithConfig(cfg)

		testEnv.Setup(
			envfuncs.SetupCRDs(testEnvConfig.CRDConfigLocation, testEnvConfig.CRDConfigPattern),
			WaitForAPIExt(kubeConfigPath, 30*time.Second),
		)

		testEnv.Finish(
			envfuncs.TeardownCRDs(testEnvConfig.CRDConfigLocation, testEnvConfig.CRDConfigPattern),
		)
	} else {
		cfg, _ = envconf.NewFromFlags()
		testEnv = env.NewWithConfig(cfg)

		clusterNamePrefix := "e2etest"
		if testEnvConfig.ClusterNamePrefix != "" {
			clusterNamePrefix = testEnvConfig.ClusterNamePrefix
		}

		clusterName := envconf.RandomName(clusterNamePrefix, 16)
		kubeConfigPath, _ := GetK3dClusterConfigPath(clusterName)

		k3sVersion := "v1.26.6+k3s1"
		if version, ok := os.LookupEnv("K3S_VERSION"); ok {
			k3sVersion = version
		}

		testEnv.Setup(
			CreateK3dCluster(clusterName, k3sVersion),
			envfuncs.SetupCRDs(testEnvConfig.CRDConfigLocation, testEnvConfig.CRDConfigPattern),
			WaitForAPIExt(kubeConfigPath, 30*time.Second),
		)

		testEnv.Finish(
			DestroyK3dCluster(clusterName),
			envfuncs.TeardownCRDs(testEnvConfig.CRDConfigLocation, testEnvConfig.CRDConfigPattern),
		)
	}

	return &TestEnvironment{
		Environment: testEnv,
		Config:      cfg,
	}
}
