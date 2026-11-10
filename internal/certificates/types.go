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
	// Emudhra tests if clients trust the publicly compromised eMudhra intermediate CA
	// (see https://emudhra.we-have-a-problem.com/ and mitmproxy PR #8500).
	// It serves the chain to emSign ECC Root CA - G3 first (modern trust stores).
	Emudhra
	// EmudhraAAA signs with the same compromised key but serves the chain
	// cross-signed by Sectigo's AAA Certificate Services first, for older or
	// frozen trust stores (mitmproxy's --emudhra-old ordering). OpenSSL-style
	// clients only follow the first chain they are given, so both orders must
	// be tried to cover both trust-store populations.
	EmudhraAAA
)

// IsEmudhra reports whether the test type signs with the compromised eMudhra key
func (t TestType) IsEmudhra() bool {
	return t == Emudhra || t == EmudhraAAA
}

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
	case Emudhra:
		return "Compromised CA (eMudhra) (Type 4)"
	case EmudhraAAA:
		return "Compromised CA (eMudhra via Sectigo AAA) (Type 5)"
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

	// Compromised eMudhra CA material (EM OV TLS CA - G3C), used by the
	// Emudhra test type; parsed and validated at NewManager time
	emudhra *emudhraChain

	// EmudhraChainMode selects which compromised chain variant is served:
	// "modern", "old" or "both" (default). Set via SetEmudhraChainMode.
	EmudhraChainMode string
}

// Logger interface for logging
type Logger interface {
	Debugf(format string, v ...interface{})
	Verbosef(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Errorf(format string, v ...interface{})
}
