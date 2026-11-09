package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newEmudhraTestManager creates a manager with the embedded eMudhra material
func newEmudhraTestManager(t *testing.T) *Manager {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "certmitm-emudhra-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	manager := &Manager{
		CertDir:          tempDir,
		CertCache:        make(map[string]*CertificatePair),
		emudhra:          mustParseEmudhraTest(t),
		EmudhraChainMode: EmudhraChainBoth,
		logger:           &noopTestLogger{},
	}
	return manager
}

type noopTestLogger struct{}

func (l *noopTestLogger) Debugf(format string, v ...interface{})   {}
func (l *noopTestLogger) Verbosef(format string, v ...interface{}) {}
func (l *noopTestLogger) Infof(format string, v ...interface{})    {}
func (l *noopTestLogger) Errorf(format string, v ...interface{})   {}

func mustParseEmudhraTest(t *testing.T) *emudhraChain {
	t.Helper()
	ec, err := parseEmudhraChain()
	if err != nil {
		t.Fatalf("Failed to parse eMudhra chain material: %v", err)
	}
	return ec
}

func TestParseEmudhraChain(t *testing.T) {
	ec := mustParseEmudhraTest(t)

	if ec.modernIntermediate.Subject.CommonName != "EM OV TLS CA - G3C" {
		t.Errorf("Unexpected modern intermediate subject: %s", ec.modernIntermediate.Subject.CommonName)
	}
	if ec.oldIntermediate.Subject.CommonName != "EM OV TLS CA - G3C" {
		t.Errorf("Unexpected old intermediate subject: %s", ec.oldIntermediate.Subject.CommonName)
	}
	if ec.crossSignedRoot.Subject.CommonName != "emSign Root TLS CA - G3" {
		t.Errorf("Unexpected cross-signed root subject: %s", ec.crossSignedRoot.Subject.CommonName)
	}
	if ec.modernIntermediate.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("Unexpected intermediate signature algorithm: %s", ec.modernIntermediate.SignatureAlgorithm)
	}
}

func TestGenerateEmudhraCertificate(t *testing.T) {
	manager := newEmudhraTestManager(t)

	cert, err := manager.GenerateCertificate("example.com", Emudhra)
	if err != nil {
		t.Fatalf("Failed to generate eMudhra certificate: %v", err)
	}

	// The leaf must be signed by the compromised CA key
	leafCert, err := x509.ParseCertificate(cert.TLSCert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse generated leaf certificate: %v", err)
	}
	if leafCert.Subject.CommonName != "example.com" {
		t.Errorf("Unexpected leaf subject: %s", leafCert.Subject.CommonName)
	}
	if leafCert.DNSNames[0] != "example.com" {
		t.Errorf("Unexpected leaf DNS name: %s", leafCert.DNSNames[0])
	}
	if err := leafCert.CheckSignatureFrom(manager.emudhra.modernIntermediate); err != nil {
		t.Errorf("Leaf certificate was not signed by compromised CA key: %v", err)
	}
	if leafCert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("Unexpected leaf signature algorithm: %s", leafCert.SignatureAlgorithm)
	}

	// The served chain must include the full compromised CA chain per mode
	chainModes := map[string]int{
		EmudhraChainModern: 3, // leaf + G3C + emSign cross-signed root
		EmudhraChainOld:    2, // leaf + G3C (AAA cross-signed)
		EmudhraChainBoth:   4, // leaf + G3C + cross-signed root + G3C (AAA)
	}
	for mode, wantLen := range chainModes {
		manager.EmudhraChainMode = mode
		manager.CertCache = make(map[string]*CertificatePair)
		certMode, err := manager.GenerateCertificate("example.com", Emudhra)
		if err != nil {
			t.Fatalf("Failed to generate eMudhra certificate (mode %s): %v", mode, err)
		}
		if got := len(certMode.TLSCert.Certificate); got != wantLen {
			t.Errorf("Chain length for mode %s: got %d, want %d", mode, got, wantLen)
		}
		// The first served intermediate is always the G3C variant
		intermediate, err := x509.ParseCertificate(certMode.TLSCert.Certificate[1])
		if err != nil {
			t.Fatalf("Failed to parse served intermediate: %v", err)
		}
		if intermediate.Subject.CommonName != "EM OV TLS CA - G3C" {
			t.Errorf("Unexpected served intermediate subject: %s", intermediate.Subject.CommonName)
		}
	}
}

func TestEmudhraChainSelectionModes(t *testing.T) {
	ec := mustParseEmudhraTest(t)

	both := ec.chainDER(EmudhraChainBoth)
	if len(both) != 3 {
		t.Errorf("Expected 3 chain certificates in both mode, got %d", len(both))
	}
	modern := ec.chainDER(EmudhraChainModern)
	if len(modern) != 2 {
		t.Errorf("Expected 2 chain certificates in modern mode, got %d", len(modern))
	}
	old := ec.chainDER(EmudhraChainOld)
	if len(old) != 1 {
		t.Errorf("Expected 1 chain certificate in old mode, got %d", len(old))
	}
}

func TestEmudhraSaveAndReloadCertificate(t *testing.T) {
	manager := newEmudhraTestManager(t)

	certPair, err := manager.GenerateCertificate("example.com", Emudhra)
	if err != nil {
		t.Fatalf("Failed to generate eMudhra certificate: %v", err)
	}

	if err := manager.saveCertificate("example.com", Emudhra, certPair); err != nil {
		t.Fatalf("Failed to save eMudhra certificate: %v", err)
	}

	// cert.pem must contain the full served chain
	certPEM, err := os.ReadFile(filepath.Join(manager.CertDir, "emudhra", "example.com", "cert.pem"))
	if err != nil {
		t.Fatalf("Failed to read saved certificate: %v", err)
	}
	chainCount := strings.Count(string(certPEM), "-----BEGIN CERTIFICATE-----")
	if chainCount != 4 {
		t.Errorf("Expected 4 certificates in saved emudhra cert.pem (leaf + 3 chain), got %d", chainCount)
	}

	// The saved pair must reload as a valid TLS certificate with full chain
	tlsCert, err := tls.LoadX509KeyPair(
		filepath.Join(manager.CertDir, "emudhra", "example.com", "cert.pem"),
		filepath.Join(manager.CertDir, "emudhra", "example.com", "key.pem"),
	)
	if err != nil {
		t.Fatalf("Failed to reload saved eMudhra certificate: %v", err)
	}
	if len(tlsCert.Certificate) != 4 {
		t.Errorf("Expected full chain from reload, got %d certificates", len(tlsCert.Certificate))
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse reloaded leaf: %v", err)
	}
	if err := leaf.CheckSignatureFrom(manager.emudhra.modernIntermediate); err != nil {
		t.Errorf("Reloaded leaf is not signed by compromised CA key: %v", err)
	}

	// Saved PEM must be decodable block by block
	firstBlock, _ := pem.Decode(certPEM)
	if firstBlock == nil || firstBlock.Type != "CERTIFICATE" {
		t.Errorf("First block of saved cert.pem is not a certificate")
	}
}
