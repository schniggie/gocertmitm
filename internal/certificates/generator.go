package certificates

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
	"time"
)

// GenerateCA creates a new certificate authority
func (m *Manager) GenerateCA() (*CertificateAuthority, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Prepare certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10 years

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "CertMITM Root CA",
			Organization:       []string{"CertMITM"},
			OrganizationalUnit: []string{"Security Testing"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Save CA certificate and private key
	if err := m.saveCA(cert, privateKey); err != nil {
		return nil, fmt.Errorf("failed to save CA: %v", err)
	}

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  privateKey,
	}, nil
}

// GenerateCertificate generates a certificate for the given domain
func (m *Manager) GenerateCertificate(domain string, testType TestType) (*CertificatePair, error) {
	// Check if certificate is already in cache
	m.cacheMutex.RLock()
	cachedCert, ok := m.CertCache[domain]
	m.cacheMutex.RUnlock()
	if ok {
		return cachedCert, nil
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Prepare certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour) // 1 day

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         domain,
			Organization:       []string{"CertMITM"},
			OrganizationalUnit: []string{"Security Testing"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add DNS names and IP addresses
	template.DNSNames = append(template.DNSNames, domain)
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	var derBytes []byte
	var parentCert *x509.Certificate
	var parentKey *rsa.PrivateKey

	switch testType {
	case SelfSigned:
		// Self-signed certificate
		parentCert = &template
		parentKey = privateKey
	case ReplacedKey:
		// Certificate signed by CA but with a different key
		parentCert = m.CA.Certificate
		parentKey = m.CA.PrivateKey
		// Generate a new key for the certificate
		newKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new key: %v", err)
		}
		privateKey = newKey
	case RealCertificate:
		// Use a real certificate for a different domain
		realCert, realKey, err := m.loadRealCertificate(domain)
		if err != nil {
			m.logger.Errorf("Failed to load real certificate for %s: %v", domain, err)
			// Fall back to CA-signed if real certificate not found
			parentCert = m.CA.Certificate
			parentKey = m.CA.PrivateKey
		} else {
			m.logger.Debugf("Successfully loaded real certificate for %s", domain)

			// Try to load the certificate directly from files
			certPath := filepath.Join(m.CertDir, "real", domain, "cert.pem")
			keyPath := filepath.Join(m.CertDir, "real", domain, "key.pem")
			fullchainPath := filepath.Join(m.CertDir, "real", domain, "fullchain.pem")

			// Determine which certificate file to use
			var useCertPath string
			if _, err := os.Stat(fullchainPath); err == nil {
				useCertPath = fullchainPath
				m.logger.Debugf("Using fullchain.pem for TLS certificate")
			} else {
				useCertPath = certPath
				m.logger.Debugf("Using cert.pem for TLS certificate")
			}

			// Load the certificate
			tlsCert, err := tls.LoadX509KeyPair(useCertPath, keyPath)
			if err != nil {
				m.logger.Errorf("Failed to load X509 key pair: %v", err)

				// If direct loading fails, create the TLS certificate manually
				tlsCert = tls.Certificate{
					Certificate: [][]byte{realCert.Raw},
					PrivateKey:  realKey,
				}
				m.logger.Debugf("Created TLS certificate manually for %s", domain)
			} else {
				m.logger.Debugf("Loaded TLS certificate directly from files for %s", domain)
				m.logger.Debugf("Certificate chain length: %d", len(tlsCert.Certificate))
			}

			certPair := &CertificatePair{
				Certificate: realCert,
				PrivateKey:  realKey,
				TLSCert:     tlsCert,
			}
			m.cacheMutex.Lock()
			m.CertCache[domain] = certPair
			m.cacheMutex.Unlock()

			// Log certificate details for debugging
			m.logger.Debugf("Certificate Subject: %s", realCert.Subject.CommonName)
			m.logger.Debugf("Certificate Issuer: %s", realCert.Issuer.CommonName)
			m.logger.Debugf("Certificate Valid From: %s", realCert.NotBefore)
			m.logger.Debugf("Certificate Valid To: %s", realCert.NotAfter)

			return certPair, nil
		}
	case RealCertificateAsCA:
		// Use a real certificate as CA
		caCert, caKey, err := m.loadCACertificate(domain)
		if err != nil {
			m.logger.Errorf("Failed to load CA certificate for %s: %v", domain, err)
			// Fall back to CA-signed if real CA certificate not found
			parentCert = m.CA.Certificate
			parentKey = m.CA.PrivateKey
		} else {
			m.logger.Debugf("Successfully loaded CA certificate for %s", domain)
			parentCert = caCert
			parentKey = caKey
		}
	default:
		// Default to CA-signed certificate
		parentCert = m.CA.Certificate
		parentKey = m.CA.PrivateKey
	}

	// Create certificate
	derBytes, err = x509.CreateCertificate(rand.Reader, &template, parentCert, &privateKey.PublicKey, parentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Create TLS certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}

	// Save certificate
	certPair := &CertificatePair{
		Certificate: cert,
		PrivateKey:  privateKey,
		TLSCert:     tlsCert,
	}

	// Add to cache
	m.cacheMutex.Lock()
	m.CertCache[domain] = certPair
	m.cacheMutex.Unlock()

	return certPair, nil
}

// saveCA saves the CA certificate and private key to disk
func (m *Manager) saveCA(cert *x509.Certificate, privateKey *rsa.PrivateKey) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(m.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %v", err)
	}

	// Save certificate
	certPath := filepath.Join(m.CertDir, "ca.crt")
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open ca.crt for writing: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return fmt.Errorf("failed to write ca.crt: %v", err)
	}

	// Save private key
	keyPath := filepath.Join(m.CertDir, "ca.key")
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open ca.key for writing: %v", err)
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write ca.key: %v", err)
	}

	return nil
}
