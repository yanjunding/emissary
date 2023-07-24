package certutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// GenerateRootCACert will generate a private key and a basic RootCA
func GenerateRootCACert(organization string, validDuration time.Duration) (privateKeyPem []byte, certPem []byte, err error) {
	var rsaPrivateKey *rsa.PrivateKey

	rsaPrivateKey, privateKeyPem, err = genKey()
	if err != nil {
		return privateKeyPem, certPem, err
	}
	certPem, err = genCACert(rsaPrivateKey, organization, validDuration)
	if err != nil {
		return privateKeyPem, certPem, err
	}

	return privateKeyPem, certPem, nil
}

func genKey() (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})
	return key, pemBytes, nil
}

// genCACert generates a Certificate Authority's certificate, returning PEM-encoded DER.
func genCACert(key *rsa.PrivateKey, subject string, validDuration time.Duration) ([]byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(validDuration)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{subject},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return pemBytes, nil
}
