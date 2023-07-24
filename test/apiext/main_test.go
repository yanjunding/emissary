package apiext_test

import (
	"os"
	"testing"

	"github.com/emissary-ingress/emissary/v3/test/internal/e2e"
)

var testEnv *e2e.TestEnvironment

func TestMain(m *testing.M) {
	testEnvConfig := &e2e.TestEnvironmentConfig{
		CRDConfigLocation: "../../build-output/apiext-e2e",
		CRDConfigPattern:  "*",
	}
	testEnv = e2e.NewTestEnvironment(testEnvConfig)
	os.Exit(testEnv.Environment.Run(m))
}
