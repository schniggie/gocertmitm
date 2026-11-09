package certificates

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	// Create temporary directory for certificates
	tempDir, err := os.MkdirTemp("", "certmitm-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create certificate manager
	manager := &Manager{
		CertDir:   tempDir,
		CertCache: make(map[string]*CertificatePair),
	}

	// Generate CA
	ca, err := manager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Check if CA certificate and private key were created
	if ca == nil {
		t.Fatal("CA is nil")
	}
	if ca.Certificate == nil {
		t.Fatal("CA certificate is nil")
	}
	if ca.PrivateKey == nil {
		t.Fatal("CA private key is nil")
	}

	// Check if CA certificate and private key were saved
	if _, err := os.Stat(filepath.Join(tempDir, "ca.crt")); os.IsNotExist(err) {
		t.Fatal("CA certificate file was not created")
	}
	if _, err := os.Stat(filepath.Join(tempDir, "ca.key")); os.IsNotExist(err) {
		t.Fatal("CA private key file was not created")
	}
}

func TestGenerateCertificate(t *testing.T) {
	// Create temporary directory for certificates
	tempDir, err := os.MkdirTemp("", "certmitm-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create certificate manager
	manager := &Manager{
		CertDir:   tempDir,
		CertCache: make(map[string]*CertificatePair),
		logger:    &noopTestLogger{},
	}

	// Generate CA
	ca, err := manager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	manager.CA = ca

	// Test domains
	domains := []string{
		"example.com",
		"test.example.com",
		"localhost",
		"127.0.0.1",
	}

	// Test certificate types
	testTypes := []TestType{
		SelfSigned,
		ReplacedKey,
		RealCertificate,
		RealCertificateAsCA,
	}

	// Generate certificates
	for _, domain := range domains {
		for _, testType := range testTypes {
			cert, err := manager.GenerateCertificate(domain, testType)
			if err != nil {
				t.Fatalf("Failed to generate certificate for %s with test type %d: %v", domain, testType, err)
			}

			// Check if certificate was created
			if cert == nil {
				t.Fatalf("Certificate for %s with test type %d is nil", domain, testType)
			}
			if cert.Certificate == nil {
				t.Fatalf("Certificate for %s with test type %d has nil certificate", domain, testType)
			}
			if cert.PrivateKey == nil {
				t.Fatalf("Certificate for %s with test type %d has nil private key", domain, testType)
			}
			if cert.TLSCert.Certificate == nil {
				t.Fatalf("Certificate for %s with test type %d has nil TLS certificate", domain, testType)
			}

			// Check if certificate is in cache (keyed by domain and test type)
			cacheKey := fmt.Sprintf("%s-%d", domain, testType)
			cachedCert, ok := manager.CertCache[cacheKey]
			if !ok {
				t.Fatalf("Certificate for %s with test type %d is not in cache", domain, testType)
			}
			if cachedCert != cert {
				t.Fatalf("Cached certificate for %s with test type %d is not the same as the generated certificate", domain, testType)
			}
		}
	}
}

// TestGetCertificateKeysCacheByTestType guards against serving a certificate
// generated for one test type when a different test type is requested
func TestGetCertificateKeysCacheByTestType(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "certmitm-cachetest")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := &Manager{
		CertDir:   tempDir,
		CertCache: make(map[string]*CertificatePair),
		logger:    &noopTestLogger{},
	}

	ca, err := manager.GenerateCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}
	manager.CA = ca

	if _, err := manager.GetCertificate("example.com", SelfSigned); err != nil {
		t.Fatalf("Failed to get self-signed certificate: %v", err)
	}

	pair, err := manager.GetCertificate("example.com", ReplacedKey)
	if err != nil {
		t.Fatalf("Failed to get replaced-key certificate: %v", err)
	}

	// The replaced-key certificate is signed by the CA, not by itself
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse replaced-key leaf certificate: %v", err)
	}
	if string(leaf.RawSubject) == string(leaf.RawIssuer) {
		t.Errorf("GetCertificate(%q, ReplacedKey) returned the cached self-signed certificate", "example.com")
	}
}
