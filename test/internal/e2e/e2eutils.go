package e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// GetK3dClusterConfigPath provides the path to the kubeconfig file for
// a the provided k3d cluster.
//
// This is the same path used by "CreateK3dCluster" so it can be used
// in conjunction.
func GetK3dClusterConfigPath(clusterName string) (string, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configPath := filepath.Join(homedir, ".k3d", fmt.Sprintf("kubeconfig-%s.yaml", clusterName))

	return configPath, nil
}

// CreateK3dCluster returns an env.Func that can be used with the k8s-sig e2e-framework. It can be
// called to create a k3d cluster during environment setup and will inject
// the kubeconfig into the context using the name as a key.
//
// NOTE: the returned function will update its env config with the kubeconfig file for the config client.
func CreateK3dCluster(clusterName string, k3sVersion string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {

		// args currently match Make files for generating a k3d cluster
		args := []string{
			"cluster",
			"create",
			"--wait",
			"--kubeconfig-update-default=false",
			"--k3s-arg=--disable=traefik@server:*",
			"--k3s-arg=--kubelet-arg=max-pods=255@server:*",
			"--k3s-arg=--egress-selector-mode=disabled@server:*",
		}

		if k3sVersion != "" {
			args = append(args, fmt.Sprintf("--image=docker.io/rancher/k3s:%s", k3sVersion))
		}

		args = append(args, clusterName)

		cmd := exec.CommandContext(ctx, "k3d", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return ctx, err
		}

		cmd = exec.CommandContext(ctx, "k3d", "kubeconfig", "write", clusterName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return ctx, err
		}

		configPath, err := GetK3dClusterConfigPath(clusterName)
		if err != nil {
			return ctx, err
		}

		cfg.WithKubeconfigFile(configPath)

		return ctx, nil
	}
}

// DestroyK3dCluster returns an EnvFunc that retrieves a previously saved k3d cluster in the
// context (using the name), then deletes it.
//
// NOTE: this should be used in a Environment.Finish step.
func DestroyK3dCluster(clusterName string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {

		cmd := exec.CommandContext(ctx, "k3d", "cluster", "delete", clusterName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		return ctx, cmd.Run()
	}
}

// WaitForAPIExt will check the cluster to see if emissary-apiext server is ready
// and available. This should be run after installing CRD's to ensure cluster is setup
// and TLS Certs have been injected
func WaitForAPIExt(kubeconfigPath string, waitDuration time.Duration) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		kubeConfigArg := fmt.Sprintf("--kubeconfig=%s", kubeconfigPath)

		timeoutArg := fmt.Sprintf("--timeout=%s", waitDuration.String())

		cmd := exec.CommandContext(ctx, "kubectl", kubeConfigArg, "wait", timeoutArg, "--for=condition=available", "deployment", "emissary-apiext", "-n=emissary-system")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		log.Println(fmt.Sprintf("executing cmd: %s", cmd.String()))
		log.Println("waiting for emissary-system apiext conversion webhook to be available...")
		return ctx, cmd.Run()
	}
}
