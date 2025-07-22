package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type CertificateManager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certCache  map[string]*tls.Certificate
	cacheMutex sync.RWMutex
}

func NewCertificateManager(caCertPath, caKeyPath string) (*CertificateManager, error) {
	// Use mkcert CA as default if no paths provided
	if caCertPath == "" || caKeyPath == "" {
		mkcertRoot := getMkcertCARoot()
		if mkcertRoot != "" {
			caCertPath = filepath.Join(mkcertRoot, "rootCA.pem")
			caKeyPath = filepath.Join(mkcertRoot, "rootCA-key.pem")
			logrus.WithField("ca_root", mkcertRoot).Info("Using mkcert CA as default")
		} else {
			return nil, fmt.Errorf("no CA certificate provided and mkcert CA not found")
		}
	}

	// Load CA certificate
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %v", err)
	}

	// Parse CA certificate
	caCert, err := parseCertificate(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Parse CA private key
	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	logrus.WithFields(logrus.Fields{
		"ca_cert": caCertPath,
		"ca_key":  caKeyPath,
		"subject": caCert.Subject.CommonName,
	}).Info("CA certificate loaded for dynamic cert generation")

	return &CertificateManager{
		caCert:    caCert,
		caKey:     caKey,
		certCache: make(map[string]*tls.Certificate),
	}, nil
}

func (cm *CertificateManager) GetCertificate(domain string) (*tls.Certificate, error) {
	cm.cacheMutex.RLock()
	if cert, exists := cm.certCache[domain]; exists {
		cm.cacheMutex.RUnlock()
		logrus.WithField("domain", domain).Debug("Using cached certificate")
		return cert, nil
	}
	cm.cacheMutex.RUnlock()

	// Generate new certificate for domain
	cm.cacheMutex.Lock()
	defer cm.cacheMutex.Unlock()

	// Double-check after acquiring write lock
	if cert, exists := cm.certCache[domain]; exists {
		logrus.WithField("domain", domain).Debug("Using cached certificate (race condition)")
		return cert, nil
	}

	logrus.WithField("domain", domain).Info("Generating new certificate for domain")
	cert, err := cm.generateCertificate(domain)
	if err != nil {
		return nil, err
	}

	cm.certCache[domain] = cert
	logrus.WithField("domain", domain).Info("Certificate generated and cached")
	
	return cert, nil
}

func (cm *CertificateManager) generateCertificate(domain string) (*tls.Certificate, error) {
	// Generate private key for domain certificate
	domainKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate domain private key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour * 365), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Handle IP addresses
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
		template.DNSNames = nil
	}

	// Sign certificate with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &domainKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Create tls.Certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, cm.caCert.Raw},
		PrivateKey:  domainKey,
	}

	return cert, nil
}

func getMkcertCARoot() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	
	// Check common mkcert locations
	locations := []string{
		filepath.Join(homeDir, "Library", "Application Support", "mkcert"), // macOS
		filepath.Join(homeDir, ".local", "share", "mkcert"),                // Linux
		filepath.Join(homeDir, "AppData", "Local", "mkcert"),               // Windows
	}

	for _, location := range locations {
		if _, err := os.Stat(filepath.Join(location, "rootCA.pem")); err == nil {
			return location
		}
	}

	return ""
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := decodePEMBlock(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := decodePEMBlock(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try different key formats
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}

	return nil, fmt.Errorf("failed to parse private key")
}

func decodePEMBlock(data []byte) (*pem.Block, []byte) {
	return pem.Decode(data)
}