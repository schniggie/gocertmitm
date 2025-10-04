package certificates

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// TestType represents the type of certificate test to perform
type TestType int

const (
	// SelfSigned tests if clients accept certificates signed by themselves
	SelfSigned TestType = iota
	// ReplacedKey tests if clients verify the certificate's public key
	ReplacedKey
	// RealCertificate tests if clients accept valid certificates for different domains
	RealCertificate
	// RealCertificateAsCA tests if clients accept certificates signed by valid but unauthorized CAs
	RealCertificateAsCA
	// DirectTunnel indicates that all tests failed and we should use a direct tunnel
	DirectTunnel
)

// GetTestTypeName returns a human-readable name for the test type
func (t TestType) GetTestTypeName() string {
	switch t {
	case SelfSigned:
		return "Self-Signed Certificate (Type 0)"
	case ReplacedKey:
		return "Replaced Key Certificate (Type 1)"
	case RealCertificate:
		return "Real Certificate for Different Domain (Type 2)"
	case RealCertificateAsCA:
		return "Real Certificate as CA (Type 3)"
	case DirectTunnel:
		return "Direct Tunnel (No MITM)"
	default:
		return fmt.Sprintf("Unknown Test Type (%d)", t)
	}
}

// CertConfig holds configuration for certificate generation
type CertConfig struct {
	CommonName         string
	Organization       []string
	OrganizationalUnit []string
	Country            []string
	Province           []string
	Locality           []string
	IPAddresses        []string
	DNSNames           []string
	NotBefore          time.Time
	NotAfter           time.Time
	IsCA               bool
	KeySize            int
}

// CertificateAuthority represents a certificate authority
type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// CertificatePair represents a certificate and its private key
type CertificatePair struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	TLSCert     tls.Certificate
}

// Manager handles certificate generation and storage
type Manager struct {
	CertDir       string
	CA            *CertificateAuthority
	CertCache     map[string]*CertificatePair
	cacheMutex    sync.RWMutex // Protects CertCache from concurrent access
	DefaultConfig CertConfig
	logger        Logger
}

// Logger interface for logging
type Logger interface {
	Debugf(format string, v ...interface{})
	Verbosef(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Errorf(format string, v ...interface{})
}
