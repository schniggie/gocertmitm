package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func testTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		DNSNames:     []string{"test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A single client must be served as soon as its handshake completes, without
// waiting for another TCP connection to unblock the accept loop.
func TestHandshakeListenerServesLoneConnection(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{httpsServer: &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{testTLSCert(t)}}}}
	l := newTLSHandshakeListener(inner, srv)
	defer l.Close()

	go func() {
		c, err := tls.Dial("tcp", inner.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "test.local"})
		if err == nil {
			defer c.Close()
			time.Sleep(3 * time.Second) // hold the connection open
		}
	}()

	accepted := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if c != nil {
			c.Close()
		}
		accepted <- err
	}()

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshaked connection was not handed out until another connection arrived")
	}
}

func TestHandshakeListenerCloseUnblocksAccept(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newTLSHandshakeListener(inner, &Server{httpsServer: &http.Server{TLSConfig: &tls.Config{}}})

	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	l.Close()

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}
