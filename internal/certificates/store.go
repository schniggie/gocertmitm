package certificates

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NewManager creates a new certificate manager
func NewManager(certDir string, logger Logger) (*Manager, error) {
	manager := &Manager{
		CertDir:   certDir,
		CertCache: make(map[string]*CertificatePair),
		DefaultConfig: CertConfig{
			Organization:       []string{"CertMITM"},
			OrganizationalUnit: []string{"Security Testing"},
			NotBefore:          time.Now(),
			NotAfter:           time.Now().Add(24 * time.Hour),
			KeySize:            2048,
		},
		logger: logger,
	}

	// Ensure all certificate directories exist
	if err := manager.ensureCertDirs(); err != nil {
		return nil, fmt.Errorf("failed to create certificate directories: %v", err)
	}

	// Check if CA certificate and private key exist
	caCertPath := filepath.Join(certDir, "ca.crt")
	caKeyPath := filepath.Join(certDir, "ca.key")

	_, certErr := os.Stat(caCertPath)
	_, keyErr := os.Stat(caKeyPath)

	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		// Generate new CA
		ca, err := manager.GenerateCA()
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA: %v", err)
		}
		manager.CA = ca
	} else {
		// Load existing CA
		ca, err := manager.loadCA(caCertPath, caKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA: %v", err)
		}
		manager.CA = ca
	}

	return manager, nil
}

// loadCA loads the CA certificate and private key from disk
func (m *Manager) loadCA(certPath, keyPath string) (*CertificateAuthority, error) {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to parse key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  privateKey,
	}, nil
}

// GetCertificate returns a certificate for the given domain and test type
func (m *Manager) GetCertificate(domain string, testType TestType) (*tls.Certificate, error) {
	m.logger.Debugf("Getting certificate for domain: %s with test type: %d", domain, testType)

	// Check if we have the certificate in cache first
	cacheKey := fmt.Sprintf("%s-%d", domain, testType)
	m.cacheMutex.RLock()
	certPair, ok := m.CertCache[cacheKey]
	m.cacheMutex.RUnlock()
	if ok {
		m.logger.Debugf("Using cached certificate for %s (test type: %s)", domain, testType.GetTestTypeName())
		return &certPair.TLSCert, nil
	}

	// Handle different test types
	if testType == RealCertificate {
		// For real certificates, try to load directly from files first

		// First, try to load a certificate for the specific domain
		certPath := filepath.Join(m.CertDir, "real", domain, "cert.pem")
		keyPath := filepath.Join(m.CertDir, "real", domain, "key.pem")
		fullchainPath := filepath.Join(m.CertDir, "real", domain, "fullchain.pem")

		// Check if files exist
		keyExists := false
		certExists := false
		fullchainExists := false

		if _, err := os.Stat(keyPath); err == nil {
			keyExists = true
		}
		if _, err := os.Stat(certPath); err == nil {
			certExists = true
		}
		if _, err := os.Stat(fullchainPath); err == nil {
			fullchainExists = true
		}

		// Prefer fullchain if available
		if keyExists && fullchainExists {
			m.logger.Debugf("Found fullchain.pem for %s, loading directly", domain)
			tlsCert, err := tls.LoadX509KeyPair(fullchainPath, keyPath)
			if err == nil {
				m.logger.Debugf("Successfully loaded fullchain certificate for %s", domain)
				m.logger.Debugf("Certificate chain length: %d", len(tlsCert.Certificate))
				return &tlsCert, nil
			}
			m.logger.Errorf("Failed to load fullchain certificate: %v", err)
		}

		// Fall back to cert.pem if fullchain not available
		if keyExists && certExists {
			m.logger.Debugf("Found cert.pem for %s, loading directly", domain)
			tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil {
				m.logger.Debugf("Successfully loaded certificate for %s", domain)
				return &tlsCert, nil
			}
			m.logger.Errorf("Failed to load certificate: %v", err)
		}

		// If no certificate found for this domain, try to find any real certificate
		m.logger.Debugf("No certificate found for %s, looking for any real certificate", domain)
		tlsCert, err := m.loadAnyRealCertificate()
		if err == nil {
			m.logger.Debugf("Using real certificate from another domain for %s", domain)
			return tlsCert, nil
		}
		m.logger.Errorf("Failed to load any real certificate: %v", err)
	} else {
		// For other test types, check if we have saved certificates
		certDir := m.getTestTypeCertDir(testType)
		certPath := filepath.Join(certDir, domain, "cert.pem")
		keyPath := filepath.Join(certDir, domain, "key.pem")

		// Check if files exist
		certExists := false
		keyExists := false

		if _, err := os.Stat(certPath); err == nil {
			certExists = true
		}
		if _, err := os.Stat(keyPath); err == nil {
			keyExists = true
		}

		// If both files exist, load them
		if certExists && keyExists {
			m.logger.Debugf("Found saved certificate for %s (test type: %s)", domain, testType.GetTestTypeName())
			tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err == nil {
				m.logger.Debugf("Successfully loaded saved certificate for %s", domain)

				// Parse the certificate to get the x509.Certificate
				cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
				if err == nil {
					// Check if the certificate is still valid
					now := time.Now()
					if now.Before(cert.NotAfter) && now.After(cert.NotBefore) {
						// Extract the private key
						privateKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
						if ok {
							// Create a certificate pair and add to cache
							certPair := &CertificatePair{
								Certificate: cert,
								PrivateKey:  privateKey,
								TLSCert:     tlsCert,
							}
							m.cacheMutex.Lock()
							m.CertCache[cacheKey] = certPair
							m.cacheMutex.Unlock()
							return &tlsCert, nil
						}
					} else {
						m.logger.Debugf("Saved certificate for %s is expired, generating new one", domain)
					}
				}
			} else {
				m.logger.Errorf("Failed to load saved certificate: %v", err)
			}
		}
	}

	// Fall back to generating certificate
	certPair, err := m.GenerateCertificate(domain, testType)
	if err != nil {
		m.logger.Errorf("Failed to generate certificate: %v", err)
		return nil, err
	}

	// Save the generated certificate for future use
	if testType != RealCertificate && testType != DirectTunnel {
		if err := m.saveCertificate(domain, testType, certPair); err != nil {
			m.logger.Errorf("Failed to save certificate: %v", err)
		}
	}

	// Add to cache with the proper key
	m.cacheMutex.Lock()
	m.CertCache[cacheKey] = certPair
	m.cacheMutex.Unlock()

	m.logger.Debugf("Successfully generated certificate for %s", domain)
	return &certPair.TLSCert, nil
}

// GetCertificateFunc returns a function that can be used with tls.Config.GetCertificate
func (m *Manager) GetCertificateFunc(testType TestType) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var mu sync.Mutex

	// Get test type name for logging
	testTypeName := testType.GetTestTypeName()

	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()

		// Get the server name from the client hello
		serverName := clientHello.ServerName
		m.logger.Infof("Client %s requested certificate for server: %s (Test: %s)",
			clientHello.Conn.RemoteAddr(), serverName, testTypeName)

		// If ServerName is empty, use SNI from the connection if available
		if serverName == "" {
			m.logger.Debugf("ServerName is empty, using default domain")
			serverName = "default.example.com"
		}

		// Try to get the certificate
		cert, err := m.GetCertificate(serverName, testType)
		if err != nil {
			m.logger.Errorf("Failed to get certificate for %s: %v", serverName, err)
			return nil, err
		}

		m.logger.Infof("Returning %s certificate for %s", testTypeName, serverName)
		return cert, nil
	}
}

// loadRealCertificate loads a real certificate for a domain
func (m *Manager) loadRealCertificate(domain string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Check for certificate files
	certPath := filepath.Join(m.CertDir, "real", domain, "cert.pem")
	keyPath := filepath.Join(m.CertDir, "real", domain, "key.pem")
	fullchainPath := filepath.Join(m.CertDir, "real", domain, "fullchain.pem")

	m.logger.Debugf("Looking for real certificate at: %s", certPath)
	m.logger.Debugf("Looking for real key at: %s", keyPath)
	m.logger.Debugf("Looking for fullchain at: %s", fullchainPath)

	// Check if key file exists (required)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("key file not found: %s", keyPath)
	}

	// Check which certificate file to use (fullchain preferred)
	var useCertPath string

	if _, err := os.Stat(fullchainPath); err == nil {
		useCertPath = fullchainPath
		m.logger.Debugf("Found fullchain.pem, will use it for domain: %s", domain)
	} else if _, err := os.Stat(certPath); err == nil {
		useCertPath = certPath
		m.logger.Debugf("No fullchain.pem found, using cert.pem for domain: %s", domain)
	} else {
		return nil, nil, fmt.Errorf("neither fullchain.pem nor cert.pem found for domain: %s", domain)
	}

	m.logger.Debugf("Using certificate file: %s for domain: %s", useCertPath, domain)

	// Try to load the certificate directly as a tls.Certificate first
	tlsCert, err := tls.LoadX509KeyPair(useCertPath, keyPath)
	if err == nil {
		m.logger.Debugf("Successfully loaded real certificate as tls.Certificate for domain: %s", domain)

		// Parse the certificate to get the x509.Certificate
		cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse loaded certificate: %v", err)
		}

		// Extract the private key
		privateKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not an RSA key")
		}

		// Log certificate details
		m.logger.Debugf("Certificate Subject: %s", cert.Subject.CommonName)
		m.logger.Debugf("Certificate Issuer: %s", cert.Issuer.CommonName)
		m.logger.Debugf("Certificate has %d entries in the chain", len(tlsCert.Certificate))

		return cert, privateKey, nil
	}

	m.logger.Debugf("Could not load as tls.Certificate, trying manual parsing: %v", err)

	// If direct loading fails, try manual parsing
	// Load certificate
	certPEM, err := os.ReadFile(useCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	// Parse all certificates in the chain
	var certDERBlock *pem.Block
	var certificates [][]byte

	for {
		certDERBlock, certPEM = pem.Decode(certPEM)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			certificates = append(certificates, certDERBlock.Bytes)
		}
	}

	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in %s", useCertPath)
	}

	m.logger.Debugf("Found %d certificates in the chain", len(certificates))

	// Parse the first certificate (leaf)
	cert, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse key PEM")
	}

	// Try different key formats
	var privateKey *rsa.PrivateKey

	// Try PKCS1
	privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		m.logger.Debugf("Failed to parse as PKCS1 key: %v", err)

		// Try PKCS8
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			m.logger.Debugf("Failed to parse as PKCS8 key: %v", err)
			return nil, nil, fmt.Errorf("failed to parse private key in any format")
		}

		var ok bool
		privateKey, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not an RSA key")
		}
	}

	m.logger.Debugf("Successfully parsed real certificate and key for domain: %s", domain)
	m.logger.Debugf("Certificate Subject: %s", cert.Subject.CommonName)
	m.logger.Debugf("Certificate Issuer: %s", cert.Issuer.CommonName)

	return cert, privateKey, nil
}

// loadCACertificate loads a certificate to be used as a CA
func (m *Manager) loadCACertificate(domain string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Check if certificate exists
	certPath := filepath.Join(m.CertDir, "ca", domain, "cert.pem")
	keyPath := filepath.Join(m.CertDir, "ca", domain, "key.pem")

	// Check if files exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("CA certificate file not found: %s", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("CA key file not found: %s", keyPath)
	}

	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate file: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA key file: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse CA key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %v", err)
	}

	return cert, privateKey, nil
}
