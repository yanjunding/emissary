package apiext

import (
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func caSecretPredicate(secretName string, secretNamespace string) func(client.Object) bool {
	return func(obj client.Object) bool {
		secret, ok := obj.(*corev1.Secret)
		if !ok || secret == nil {
			return false
		}

		if secret.Name == secretName && secret.Namespace == secretNamespace {
			return true
		}

		return false
	}
}
