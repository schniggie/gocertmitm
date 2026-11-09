package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// getTestTypeCertDir returns the directory for storing certificates of a specific test type
func (m *Manager) getTestTypeCertDir(testType TestType) string {
	var dirName string

	switch testType {
	case SelfSigned:
		dirName = "self-signed"
	case ReplacedKey:
		dirName = "replaced-key"
	case RealCertificateAsCA:
		dirName = "real-ca"
	case Emudhra:
		dirName = "emudhra"
	default:
		dirName = "unknown"
	}

	return filepath.Join(m.CertDir, dirName)
}

// saveCertificate saves a certificate to disk for future use
func (m *Manager) saveCertificate(domain string, testType TestType, certPair *CertificatePair) error {
	// Skip saving for certain test types
	if testType == RealCertificate || testType == DirectTunnel {
		return nil
	}

	// Get the directory for this test type
	certDir := m.getTestTypeCertDir(testType)

	// Create domain directory
	domainDir := filepath.Join(certDir, sanitizePathName(domain))
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return fmt.Errorf("failed to create domain directory: %v", err)
	}

	// Save certificate; for types with a served intermediate chain (such as
	// eMudhra), write the full chain so reloads keep the complete handshake
	certPath := filepath.Join(domainDir, "cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certOut.Close()

	chainCertificates := [][]byte{certPair.Certificate.Raw}
	if testType == Emudhra && len(certPair.TLSCert.Certificate) > 0 {
		chainCertificates = certPair.TLSCert.Certificate
	}
	for _, chainCert := range chainCertificates {
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: chainCert}); err != nil {
			return fmt.Errorf("failed to write certificate: %v", err)
		}
	}

	// Save private key with restrictive permissions so intercepted key
	// material is not readable by other users on the host
	keyPath := filepath.Join(domainDir, "key.pem")
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(certPair.PrivateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	m.logger.Debugf("Saved certificate for %s (test type: %s)", domain, testType.GetTestTypeName())
	return nil
}

// sanitizePathName makes a user-controlled value (such as the SNI from a
// client hello) safe to use as a directory name so it cannot traverse outside
// the certificate directory
func sanitizePathName(name string) string {
	if name == "" {
		return "unknown-domain"
	}
	s := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 || r < 32 || r == 127 {
			return '_'
		}
		return r
	}, name)
	switch s {
	case ".", "..":
		return "unknown-domain"
	}
	return s
}

// ensureCertDirs ensures that all certificate directories exist
func (m *Manager) ensureCertDirs() error {
	// Create main certificate directory
	if err := os.MkdirAll(m.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %v", err)
	}

	// Create directories for each test type
	testTypes := []struct {
		Type TestType
		Dir  string
	}{
		{SelfSigned, "self-signed"},
		{ReplacedKey, "replaced-key"},
		{RealCertificate, "real"},
		{RealCertificateAsCA, "real-ca"},
		{Emudhra, "emudhra"},
	}

	for _, tt := range testTypes {
		dir := filepath.Join(m.CertDir, tt.Dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create %s directory: %v", tt.Dir, err)
		}
	}

	return nil
}
