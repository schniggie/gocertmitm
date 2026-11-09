package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/logging"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never started listening", addr)
}

// startTestProxy runs a full proxy (HTTP + HTTPS listeners) in auto-test mode
func startTestProxy(t *testing.T) (*Server, string) {
	t.Helper()
	t.Chdir(t.TempDir()) // tester and payload logger write relative to cwd

	logger, err := logging.NewLogger(t.TempDir(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Close() })

	certManager, err := certificates.NewManager(t.TempDir(), logger)
	if err != nil {
		t.Fatal(err)
	}

	httpAddr, httpsAddr := freeAddr(t), freeAddr(t)
	srv, err := NewServer(httpAddr, httpsAddr, certManager, logger, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetTestType(certificates.SelfSigned)
	srv.SetAutoTest(true)
	if err := srv.SetPayloadDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop() })
	waitListening(t, httpAddr)
	waitListening(t, httpsAddr)
	return srv, httpAddr
}

// testHost is a dotted name (upstream skips dotless hosts such as localhost);
// routeRelayTo points the proxy's upstream dialer at the local target so the
// name never needs to resolve
const testHost = "app.mitm.test"

func routeRelayTo(srv *Server, target string) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	srv.regularTransport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, target)
	}
}

func proxyClient(proxyAddr string, insecure bool) *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
			DisableKeepAlives: true,
		},
	}
}

// A client that accepts any certificate must get the real response through
// an explicit CONNECT tunnel, and the domain must be recorded as vulnerable
func TestConnectInterceptsAcceptingClient(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	}))
	defer target.Close()
	_, port, _ := net.SplitHostPort(target.Listener.Addr().String())

	srv, proxyAddr := startTestProxy(t)
	routeRelayTo(srv, target.Listener.Addr().String())

	resp, err := proxyClient(proxyAddr, true).Get("https://" + testHost + ":" + port + "/secret")
	if err != nil {
		t.Fatalf("request through CONNECT failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello /secret" {
		t.Fatalf("unexpected response %d %q", resp.StatusCode, body)
	}

	view, ok := srv.Domain(testHost)
	if !ok || view.Verdict != VerdictVulnerable || view.AcceptedTest != "self-signed" {
		t.Fatalf("expected %s vulnerable to self-signed, got %+v (ok=%v)", testHost, view, ok)
	}
	for _, d := range srv.Domains() {
		if strings.Contains(d.Key, ":") {
			t.Fatalf("CONNECT created a host:port domain entry %q", d.Key)
		}
	}
}

// A verifying client must reject the forged certificate, and the rejection
// must be recorded against the SNI hostname
func TestConnectRecordsRejection(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()
	_, port, _ := net.SplitHostPort(target.Listener.Addr().String())

	srv, proxyAddr := startTestProxy(t)

	if _, err := proxyClient(proxyAddr, false).Get("https://" + testHost + ":" + port + "/"); err == nil {
		t.Fatal("verifying client accepted a forged certificate")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if view, ok := srv.Domain(testHost); ok {
			for _, tv := range view.Tests {
				if tv.Key == "self-signed" && tv.State == TestStateRejected {
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	view, _ := srv.Domain(testHost)
	t.Fatalf("rejection not recorded: %+v", view)
}

// Non-TLS payloads inside a CONNECT tunnel are relayed unchanged
func TestConnectSplicesNonTLS(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	_, proxyAddr := startTestProxy(t)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr())
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT not established: %q %v", status, err)
	}
	for line, _ := br.ReadString('\n'); line != "\r\n" && line != ""; line, _ = br.ReadString('\n') {
	}

	fmt.Fprint(conn, "PING plain text\n")
	reply, err := br.ReadString('\n')
	if err != nil || reply != "PING plain text\n" {
		t.Fatalf("splice failed: %q %v", reply, err)
	}
}
