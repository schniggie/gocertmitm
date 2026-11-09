package certificates

import (
	"crypto/ecdsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
)

//go:embed assets/emudhra_key.pem assets/emudhra_modern_1_g3c_emsign.pem assets/emudhra_modern_2_crossroot.pem assets/emudhra_old_g3c_aaa.pem assets/emudhra_root_aaa.pem assets/emudhra_root_emsign_ecc.pem
var emudhraAssets embed.FS

// Emudhra chain selection modes
const (
	// EmudhraChainModern serves the chain via emSign Root TLS CA - G3 (cross-signed
	// by emSign ECC Root CA - G3), present in all modern trust stores.
	EmudhraChainModern = "modern"
	// EmudhraChainOld serves the chain cross-signed by AAA Certificate Services
	// (Sectigo), present in older or frozen pre-2021 trust stores.
	EmudhraChainOld = "old"
	// EmudhraChainBoth serves both variants, modern variant first.
	EmudhraChainBoth = "both"
)

// emudhraChain holds the publicly disclosed eMudhra "EM OV TLS CA - G3C"
// compromised intermediate CA material. The private keys of eight eMudhra
// intermediates were publicly disclosed on 2026-10-20 because they can be
// recovered from the certificates themselves (flawed key generation).
// See https://emudhra.we-have-a-problem.com/ and mitmproxy PR #8500.
type emudhraChain struct {
	// intermediate Modern is the "EM OV TLS CA - G3C" copy issued by
	// "emSign Root TLS CA - G3" (chaining to emSign ECC Root CA - G3)
	modernIntermediate *x509.Certificate
	// crossSignedRoot is the "emSign Root TLS CA - G3" copy cross-signed by
	// the trusted "emSign ECC Root CA - G3" root
	crossSignedRoot *x509.Certificate
	// oldIntermediate is the "EM OV TLS CA - G3C" copy cross-signed by the
	// "AAA Certificate Services" (Sectigo) root
	oldIntermediate *x509.Certificate

	// trusted roots used for startup validation only, never served
	rootAaa       *x509.Certificate
	rootEmSignECC *x509.Certificate

	// compromised CA private key, shared by both intermediate variants
	privateKey *ecdsa.PrivateKey
}

// parseEmudhraChain loads and validates the embedded eMudhra chain material
func parseEmudhraChain() (*emudhraChain, error) {
	ec := &emudhraChain{}

	keyPEM, err := emudhraAssets.ReadFile("assets/emudhra_key.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read eMudhra key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to parse eMudhra key PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse eMudhra private key: %v", err)
	}
	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("eMudhra private key is not ECDSA")
	}
	ec.privateKey = privateKey

	modernPEM, err := emudhraAssets.ReadFile("assets/emudhra_modern_1_g3c_emsign.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read eMudhra modern intermediate: %v", err)
	}
	if ec.modernIntermediate, err = parsePEMCertificate(modernPEM); err != nil {
		return nil, fmt.Errorf("failed to parse eMudhra modern intermediate: %v", err)
	}

	crossRootPEM, err := emudhraAssets.ReadFile("assets/emudhra_modern_2_crossroot.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read eMudhra cross-signed root: %v", err)
	}
	if ec.crossSignedRoot, err = parsePEMCertificate(crossRootPEM); err != nil {
		return nil, fmt.Errorf("failed to parse eMudhra cross-signed root: %v", err)
	}

	oldPEM, err := emudhraAssets.ReadFile("assets/emudhra_old_g3c_aaa.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read eMudhra old intermediate: %v", err)
	}
	if ec.oldIntermediate, err = parsePEMCertificate(oldPEM); err != nil {
		return nil, fmt.Errorf("failed to parse eMudhra old intermediate: %v", err)
	}

	if ec.privateKey == nil {
		return nil, fmt.Errorf("eMudhra private key was not loaded")
	}
	rootAaaSrc, err := emudhraAssets.ReadFile("assets/emudhra_root_aaa.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read eMudhra AAA root: %v", err)
	}
	aaaRoot, err := parsePEMCertificate(rootAaaSrc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse eMudhra AAA root: %v", err)
	}

	rootEmSignSrc, err := emudhraAssets.ReadFile("assets/emudhra_root_emsign_ecc.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read eMudhra emSign root: %v", err)
	}
	emSignRoot, err := parsePEMCertificate(rootEmSignSrc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse eMudhra emSign root: %v", err)
	}

	ec.rootAaa = aaaRoot
	ec.rootEmSignECC = emSignRoot

	if err := ec.validate(); err != nil {
		return nil, fmt.Errorf("eMudhra chain validation failed: %v", err)
	}

	return ec, nil
}

// parsePEMCertificate decodes the first CERTIFICATE block of a PEM file
func parsePEMCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// validate checks that the material is internally consistent:
// - the private key matches both intermediate variants' public keys
// - each intermediate variant's signature is valid against its issuer
// - the cross-signed root verifies against the emSign ECC Root CA - G3 root
func (ec *emudhraChain) validate() error {
	if ec.modernIntermediate.PublicKeyAlgorithm != x509.ECDSA {
		return fmt.Errorf("eMudhra intermediate is not ECDSA")
	}
	modernPub, ok := ec.modernIntermediate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("eMudhra intermediate public key is not ECDSA")
	}
	if !ec.privateKey.PublicKey.Equal(modernPub) {
		return fmt.Errorf("eMudhra private key does not match modern intermediate certificate")
	}

	oldPub, ok := ec.oldIntermediate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("eMudhra old intermediate public key is not ECDSA")
	}
	if !ec.privateKey.PublicKey.Equal(oldPub) {
		return fmt.Errorf("eMudhra private key does not match old intermediate certificate")
	}

	if err := ec.modernIntermediate.CheckSignatureFrom(ec.crossSignedRoot); err != nil {
		return fmt.Errorf("eMudhra modern intermediate does not chain to cross-signed root: %v", err)
	}
	if err := ec.crossSignedRoot.CheckSignatureFrom(ec.rootEmSignECC); err != nil {
		return fmt.Errorf("eMudhra cross-signed root does not chain to emSign ECC Root CA - G3: %v", err)
	}
	if err := ec.oldIntermediate.CheckSignatureFrom(ec.rootAaa); err != nil {
		return fmt.Errorf("eMudhra old intermediate does not chain to AAA Certificate Services: %v", err)
	}

	return nil
}

// leafSigner returns the compromised CA key and certificate to sign leaf
// certificates with
func (ec *emudhraChain) leafSigner() (*x509.Certificate, *ecdsa.PrivateKey) {
	return ec.modernIntermediate, ec.privateKey
}

// chainDER returns the intermediate certificates that must be served in the
// TLS handshake for the given mode, leaf-first not included
func (ec *emudhraChain) chainDER(mode string) [][]byte {
	switch mode {
	case EmudhraChainModern:
		return [][]byte{ec.modernIntermediate.Raw, ec.crossSignedRoot.Raw}
	case EmudhraChainOld:
		return [][]byte{ec.oldIntermediate.Raw}
	default:
		// Including both variants in one handshake; OpenSSL-style clients
		// only consider the first chain, so the modern one comes first
		return [][]byte{
			ec.modernIntermediate.Raw,
			ec.crossSignedRoot.Raw,
			ec.oldIntermediate.Raw,
		}
	}
}
