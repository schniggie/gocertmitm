package certificates

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

const emudhraTestHost = "victim.example.com"

// emudhraCase is one served configuration and the trust stores it must reach
// with an OpenSSL-style (first chain only) verifier
type emudhraCase struct {
	name      string
	testType  TestType
	mode      string
	emSignECC bool // reaches emSign ECC Root CA - G3 (modern trust stores)
	aaa       bool // reaches AAA Certificate Services (old / frozen stores)
}

var emudhraCases = []emudhraCase{
	{"emudhra/both", Emudhra, EmudhraChainBoth, true, false},
	{"emudhra/modern", Emudhra, EmudhraChainModern, true, false},
	{"emudhra/old", Emudhra, EmudhraChainOld, false, true},
	{"emudhra-aaa", EmudhraAAA, EmudhraChainBoth, false, true},
}

// servedChain generates the handshake chain for a case
func servedChain(t *testing.T, m *Manager, c emudhraCase) []*x509.Certificate {
	t.Helper()
	m.EmudhraChainMode = c.mode
	m.CertCache = make(map[string]*CertificatePair)
	pair, err := m.GenerateCertificate(emudhraTestHost, c.testType)
	if err != nil {
		t.Fatalf("%s: generate: %v", c.name, err)
	}
	chain := make([]*x509.Certificate, 0, len(pair.TLSCert.Certificate))
	for _, der := range pair.TLSCert.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("%s: parse served cert: %v", c.name, err)
		}
		chain = append(chain, cert)
	}
	return chain
}

// firstChainReaches mimics a verifier that, like OpenSSL, picks the first
// served certificate whose subject matches the current issuer and never
// backtracks. It checks names, signatures, validity, CA/key usage flags and
// the serverAuth EKU, then whether the path ends at root. Go's own Verify
// cannot be used for this: Go hard-distrusts the leaked keys (see
// TestGoDistrustsLeakedEmudhraKeys).
func firstChainReaches(served []*x509.Certificate, root *x509.Certificate, now time.Time) bool {
	leaf := served[0]
	if leaf.VerifyHostname(emudhraTestHost) != nil || now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return false
	}
	current := leaf
	for depth := 0; depth < len(served); depth++ {
		if bytes.Equal(current.RawIssuer, root.RawSubject) {
			return current.CheckSignatureFrom(root) == nil
		}
		next := -1
		for i, cand := range served[1:] {
			if bytes.Equal(cand.RawSubject, current.RawIssuer) {
				next = i + 1
				break // first match only, no backtracking
			}
		}
		if next < 0 {
			return false
		}
		issuer := served[next]
		if current.CheckSignatureFrom(issuer) != nil ||
			now.Before(issuer.NotBefore) || now.After(issuer.NotAfter) ||
			(len(issuer.ExtKeyUsage) > 0 && !slices.Contains(issuer.ExtKeyUsage, x509.ExtKeyUsageServerAuth)) {
			return false
		}
		current = issuer
	}
	return false
}

func TestEmudhraChainsReachExpectedTrustStores(t *testing.T) {
	m := newEmudhraTestManager(t)
	now := time.Now()

	for _, c := range emudhraCases {
		served := servedChain(t, m, c)
		if got := firstChainReaches(served, m.emudhra.rootEmSignECC, now); got != c.emSignECC {
			t.Errorf("%s: reaches emSign ECC Root CA - G3 = %v, want %v", c.name, got, c.emSignECC)
		}
		if got := firstChainReaches(served, m.emudhra.rootAaa, now); got != c.aaa {
			t.Errorf("%s: reaches AAA Certificate Services = %v, want %v", c.name, got, c.aaa)
		}
	}
}

// The same matrix checked by a real OpenSSL verifier, the TLS stack most
// embedded and IoT clients use
func TestEmudhraChainsWithOpenSSL(t *testing.T) {
	opensslBin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	m := newEmudhraTestManager(t)
	dir := t.TempDir()

	writePEM := func(name string, certs ...*x509.Certificate) string {
		path := filepath.Join(dir, name)
		var buf bytes.Buffer
		for _, c := range certs {
			_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	roots := map[string]*x509.Certificate{
		"emSign": m.emudhra.rootEmSignECC,
		"AAA":    m.emudhra.rootAaa,
	}

	for _, c := range emudhraCases {
		served := servedChain(t, m, c)
		leafPath := writePEM("leaf.pem", served[0])
		untrustedPath := writePEM("untrusted.pem", served[1:]...)

		for rootName, root := range roots {
			rootPath := writePEM("root.pem", root)
			cmd := exec.Command(opensslBin, "verify", "-no-CApath", "-CAfile", rootPath,
				"-untrusted", untrustedPath, "-purpose", "sslserver",
				"-verify_hostname", emudhraTestHost, leafPath)
			out, err := cmd.CombinedOutput()
			want := c.emSignECC
			if rootName == "AAA" {
				want = c.aaa
			}
			if got := err == nil; got != want {
				t.Errorf("%s vs %s root: openssl verified=%v want %v\n%s", c.name, rootName, got, want, out)
			}
		}
	}
}

// Go 1.27 ships a built-in SPKI distrust list containing the eight leaked
// eMudhra intermediate keys, so Go clients reject these chains whatever their
// trust store contains. This pins that behaviour so a change is noticed.
func TestGoDistrustsLeakedEmudhraKeys(t *testing.T) {
	m := newEmudhraTestManager(t)
	served := servedChain(t, m, emudhraCases[0])

	roots := x509.NewCertPool()
	roots.AddCert(m.emudhra.rootEmSignECC)
	intermediates := x509.NewCertPool()
	for _, c := range served[1:] {
		intermediates.AddCert(c)
	}
	if _, err := served[0].Verify(x509.VerifyOptions{
		DNSName:       emudhraTestHost,
		Roots:         roots,
		Intermediates: intermediates,
	}); err == nil {
		t.Fatal("Go accepted a chain signed with a leaked eMudhra key; its built-in distrust list changed")
	}
}
