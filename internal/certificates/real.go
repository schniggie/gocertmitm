package certificates

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
)

// findAnyRealCertificate searches for any available real certificate
func (m *Manager) findAnyRealCertificate() (string, string, string, error) {
	// Get the real certificates directory
	realCertDir := filepath.Join(m.CertDir, "real")

	// Check if the directory exists
	if _, err := os.Stat(realCertDir); os.IsNotExist(err) {
		return "", "", "", fmt.Errorf("real certificates directory not found: %s", realCertDir)
	}

	// List all subdirectories (domains)
	entries, err := os.ReadDir(realCertDir)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read real certificates directory: %v", err)
	}

	// Look for any domain with valid certificate files
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		domain := entry.Name()
		domainDir := filepath.Join(realCertDir, domain)

		// Check for certificate files
		certPath := filepath.Join(domainDir, "cert.pem")
		keyPath := filepath.Join(domainDir, "key.pem")
		fullchainPath := filepath.Join(domainDir, "fullchain.pem")

		// Check if key file exists (required)
		keyExists := false
		if _, err := os.Stat(keyPath); err == nil {
			keyExists = true
		}

		if !keyExists {
			continue
		}

		// Check which certificate file to use (fullchain preferred)
		fullchainExists := false
		certExists := false

		if _, err := os.Stat(fullchainPath); err == nil {
			fullchainExists = true
		}

		if _, err := os.Stat(certPath); err == nil {
			certExists = true
		}

		// If we have a key and at least one certificate file, return this domain.
		// Prefer fullchain and return the certificate file we validated so the
		// caller never receives a path that does not exist
		if keyExists && (fullchainExists || certExists) {
			certFile := certPath
			if fullchainExists {
				certFile = fullchainPath
			}
			m.logger.Debugf("Found real certificate for domain: %s", domain)
			return domain, certFile, keyPath, nil
		}
	}

	return "", "", "", fmt.Errorf("no real certificates found in %s", realCertDir)
}

// loadAnyRealCertificate loads any available real certificate
func (m *Manager) loadAnyRealCertificate() (*tls.Certificate, error) {
	// Find any real certificate
	domain, certPath, keyPath, err := m.findAnyRealCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to find any real certificate: %v", err)
	}

	// Check for fullchain.pem
	fullchainPath := filepath.Join(m.CertDir, "real", domain, "fullchain.pem")
	fullchainExists := false

	if _, err := os.Stat(fullchainPath); err == nil {
		fullchainExists = true
	}

	// Prefer fullchain if available
	if fullchainExists {
		m.logger.Debugf("Using fullchain.pem for domain: %s", domain)
		tlsCert, err := tls.LoadX509KeyPair(fullchainPath, keyPath)
		if err == nil {
			m.logger.Debugf("Successfully loaded fullchain certificate for domain: %s", domain)
			return &tlsCert, nil
		}
		m.logger.Errorf("Failed to load fullchain certificate: %v", err)
	}

	// Fall back to cert.pem
	m.logger.Debugf("Using cert.pem for domain: %s", domain)
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		m.logger.Infof("Successfully loaded certificate for domain: %s", domain)
		return &tlsCert, nil
	}

	return nil, fmt.Errorf("failed to load certificate for domain %s: %v", domain, err)
}
