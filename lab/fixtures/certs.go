package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

func generateCerts(dir string) error {
	now := time.Now().UTC()
	if err := generateCert(dir, "tls-selfsigned", "172.30.0.23", now.Add(-time.Hour), now.AddDate(10, 0, 0)); err != nil {
		return err
	}
	expiry := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	return generateCert(dir, "tls-expired", "172.30.0.24", expiry.AddDate(-1, 0, 0), expiry)
}

func generateCert(dir, name, ip string, start, end time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate %s key: %w", name, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode %s key: %w", name, err)
	}
	cert := &x509.Certificate{
		Subject:     pkix.Name{CommonName: name + ".raven.lab"},
		NotBefore:   start,
		NotAfter:    end,
		IPAddresses: []net.IP{net.ParseIP(ip)},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create %s certificate: %w", name, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, name+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return os.WriteFile(filepath.Join(dir, name+".crt"), certPEM, 0o644)
}
