package webui

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gocertmitm/internal/events"
	"github.com/gocertmitm/internal/proxy"
)

const testToken = "0123456789abcdef0123456789abcdef"

type fakeBackend struct {
	mu         sync.Mutex
	domains    map[string]proxy.DomainView
	payloadDir string
	resets     []string
}

func (f *fakeBackend) Info() proxy.Info {
	return proxy.Info{
		HTTPAddr: ":8080", HTTPSAddr: ":8443", AutoTest: true,
		Tester: proxy.TesterConfig{TestOrder: []proxy.TestTypeInfo{{Key: "self-signed"}, {Key: "replaced-key"}}},
	}
}
func (f *fakeBackend) Stats() proxy.Stats { return proxy.Stats{ActiveClients: map[string]int{}} }
func (f *fakeBackend) Domains() []proxy.DomainView {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]proxy.DomainView, 0, len(f.domains))
	for _, d := range f.domains {
		out = append(out, d)
	}
	return out
}
func (f *fakeBackend) Domain(key string) (proxy.DomainView, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.domains[key]
	return d, ok
}
func (f *fakeBackend) ResetDomain(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.domains[key]
	if ok {
		f.resets = append(f.resets, key)
	}
	return ok
}
func (f *fakeBackend) DeleteDomain(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.domains[key]
	delete(f.domains, key)
	return ok
}
func (f *fakeBackend) CACertificatePEM() []byte {
	return []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
}
func (f *fakeBackend) PayloadDir() string { return f.payloadDir }

type nopLogger struct{}

func (nopLogger) Infof(string, ...interface{})  {}
func (nopLogger) Errorf(string, ...interface{}) {}

func newTestServer(t *testing.T, noAuth bool) (*Server, *fakeBackend, *events.Bus) {
	t.Helper()
	dir := t.TempDir()
	fb := &fakeBackend{
		domains: map[string]proxy.DomainView{
			"example.com":     {Key: "example.com", Domain: "example.com", Verdict: proxy.VerdictVulnerable, AcceptedTest: "self-signed"},
			"=cmd|' /C calc'": {Key: "=cmd|' /C calc'", Domain: "=cmd|' /C calc'", Verdict: proxy.VerdictTesting},
		},
		payloadDir: dir,
	}
	bus := events.NewBus()
	s, err := New(Config{Addr: "127.0.0.1:0", Token: testToken, NoAuth: noAuth, Backend: fb, Bus: bus, Logger: nopLogger{}})
	if err != nil {
		t.Fatal(err)
	}
	return s, fb, bus
}

func do(t *testing.T, h http.Handler, method, target string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func bearer(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testToken) }

func TestNewRejectsShortToken(t *testing.T) {
	_, err := New(Config{Token: "short", Backend: &fakeBackend{}, Bus: events.NewBus(), Logger: nopLogger{}})
	if err == nil {
		t.Fatal("expected error for short token")
	}
}

func TestAuthRequired(t *testing.T) {
	s, _, _ := newTestServer(t, false)
	h := s.Handler()

	if rec := do(t, h, "GET", "/api/domains", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("api without token: got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/", nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("index without token: got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do(t, h, "GET", "/api/domains", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong") }); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/api/domains", bearer); rec.Code != http.StatusOK {
		t.Fatalf("bearer token: got %d", rec.Code)
	}
	// Static assets and login page stay reachable
	if rec := do(t, h, "GET", "/static/app.css", nil); rec.Code != http.StatusOK {
		t.Fatalf("static: got %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/login", nil); rec.Code != http.StatusOK {
		t.Fatalf("login page: got %d", rec.Code)
	}
}

func TestTokenLinkSetsCookieAndStripsToken(t *testing.T) {
	s, _, _ := newTestServer(t, false)
	h := s.Handler()

	rec := do(t, h, "GET", "/?token="+testToken, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("token link: got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected cookie: %+v", cookies)
	}

	rec = do(t, h, "GET", "/", func(r *http.Request) { r.AddCookie(cookies[0]) })
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app.js") {
		t.Fatalf("index with cookie: got %d", rec.Code)
	}

	// A wrong token link must not set a cookie
	rec = do(t, h, "GET", "/?token=nope", nil)
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("wrong token set a cookie")
	}
}

func TestLoginForm(t *testing.T) {
	s, _, _ := newTestServer(t, false)
	h := s.Handler()

	post := func(token, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{"token": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(testToken, ""); rec.Header().Get("Location") != "/" || len(rec.Result().Cookies()) != 1 {
		t.Fatalf("valid login: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := post("bad", ""); rec.Header().Get("Location") != "/login?failed=1" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("invalid login: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := post(testToken, "http://evil.example"); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login: got %d", rec.Code)
	}
}

func TestCSRFProtection(t *testing.T) {
	s, fb, _ := newTestServer(t, false)
	h := s.Handler()

	if rec := do(t, h, "POST", "/api/domains/example.com/reset", bearer); rec.Code != http.StatusForbidden {
		t.Fatalf("reset without CSRF header: got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/domains/example.com/reset", func(r *http.Request) {
		bearer(r)
		r.Header.Set(csrfHeader, "1")
		r.Header.Set("Origin", "http://evil.example")
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("reset cross-origin: got %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/domains/example.com/reset", func(r *http.Request) {
		bearer(r)
		r.Header.Set(csrfHeader, "1")
		r.Header.Set("Origin", "http://example.com")
	}); rec.Code != http.StatusOK {
		t.Fatalf("reset same-origin: got %d %s", rec.Code, rec.Body)
	}
	if len(fb.resets) != 1 || fb.resets[0] != "example.com" {
		t.Fatalf("reset not applied: %v", fb.resets)
	}
	if rec := do(t, h, "POST", "/api/domains/unknown/reset", func(r *http.Request) { bearer(r); r.Header.Set(csrfHeader, "1") }); rec.Code != http.StatusNotFound {
		t.Fatalf("reset unknown: got %d", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/api/domains/example.com", func(r *http.Request) { bearer(r); r.Header.Set(csrfHeader, "1") }); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	s, _, _ := newTestServer(t, false)
	rec := do(t, s.Handler(), "GET", "/api/info", bearer)
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("weak CSP: %q", csp)
	}
}

func TestNoAuthHostGuard(t *testing.T) {
	s, _, _ := newTestServer(t, true)
	h := s.Handler()

	for host, want := range map[string]int{
		"127.0.0.1:8081":     http.StatusOK,
		"localhost:8081":     http.StatusOK,
		"[::1]:8081":         http.StatusOK,
		"192.168.1.1":        http.StatusOK,
		"rebind.evil.com":    http.StatusForbidden,
		"rebind.evil.com:80": http.StatusForbidden,
	} {
		rec := do(t, h, "GET", "/api/info", func(r *http.Request) { r.Host = host })
		if rec.Code != want {
			t.Errorf("Host %q: got %d want %d", host, rec.Code, want)
		}
	}
}

func writePayload(t *testing.T, dir, host, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, host), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, host, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPayloadBrowsing(t *testing.T) {
	s, fb, _ := newTestServer(t, false)
	h := s.Handler()

	writePayload(t, fb.payloadDir, "api.example.com", "req_20260101_120000.000_REQ-0001.meta", "Method: POST\n")
	writePayload(t, fb.payloadDir, "api.example.com", "req_20260101_120000.000_REQ-0001.body", "password=hunter2")
	writePayload(t, fb.payloadDir, "api.example.com", "resp_20260101_120000.100_REQ-0001.meta", "Status: 200 OK\n")
	writePayload(t, fb.payloadDir, "api.example.com", "req_20260101_120001.000_REQ-0002.meta", "Method: GET\n")
	writePayload(t, fb.payloadDir, "api.example.com", "notes.txt", "ignored")

	rec := do(t, h, "GET", "/api/payloads", bearer)
	var hosts []PayloadHost
	if err := json.Unmarshal(rec.Body.Bytes(), &hosts); err != nil || len(hosts) != 1 || hosts[0].Name != "api.example.com" || hosts[0].Files != 5 {
		t.Fatalf("hosts: %v %s", err, rec.Body)
	}

	rec = do(t, h, "GET", "/api/payloads/api.example.com", bearer)
	var exchanges []PayloadExchange
	if err := json.Unmarshal(rec.Body.Bytes(), &exchanges); err != nil || len(exchanges) != 2 {
		t.Fatalf("exchanges: %v %s", err, rec.Body)
	}
	if exchanges[0].ID != "REQ-0002" || exchanges[1].RequestBody == nil || exchanges[1].ResponseMeta == nil {
		t.Fatalf("unexpected grouping: %+v", exchanges)
	}

	rec = do(t, h, "GET", "/api/payloads/api.example.com?id=REQ-0001", bearer)
	exchanges = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &exchanges)
	if len(exchanges) != 1 || exchanges[0].ID != "REQ-0001" {
		t.Fatalf("id filter: %s", rec.Body)
	}

	rec = do(t, h, "GET", "/api/payloads/api.example.com/req_20260101_120000.000_REQ-0001.body?max=4", bearer)
	if rec.Code != http.StatusOK || rec.Body.String() != "pass" || rec.Header().Get("X-Payload-Truncated") != "1" ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("view: %d %q %v", rec.Code, rec.Body, rec.Header())
	}

	rec = do(t, h, "GET", "/api/payloads/api.example.com/req_20260101_120000.000_REQ-0001.body?download=1", bearer)
	if rec.Body.String() != "password=hunter2" || rec.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %q %v", rec.Body, rec.Header())
	}

	// Non-payload files in the directory are not served
	if rec := do(t, h, "GET", "/api/payloads/api.example.com/notes.txt", bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-payload file: got %d", rec.Code)
	}
}

func TestPayloadTraversalBlocked(t *testing.T) {
	s, fb, _ := newTestServer(t, false)
	h := s.Handler()

	// A secret next to (outside) the payload directory
	outside := filepath.Join(filepath.Dir(fb.payloadDir), "req_20260101_120000.000_REQ-0001.meta")
	if err := os.WriteFile(outside, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(outside) })

	// A symlinked host directory pointing outside must not be followed
	if err := os.Symlink(filepath.Dir(fb.payloadDir), filepath.Join(fb.payloadDir, "evil.example")); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{
		"/api/payloads/../req_20260101_120000.000_REQ-0001.meta",
		"/api/payloads/..%2F..%2Fetc/passwd",
		"/api/payloads/%2E%2E/req_20260101_120000.000_REQ-0001.meta",
		"/api/payloads/evil.example/req_20260101_120000.000_REQ-0001.meta",
		"/api/payloads/evil.example",
		"/api/payloads/..",
	} {
		rec := do(t, h, "GET", p, bearer)
		if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "SECRET") {
			t.Errorf("%s: traversal not blocked (%d %q)", p, rec.Code, rec.Body)
		}
	}
}

func TestParsePayloadName(t *testing.T) {
	dir, ts, id, kind, ok := parsePayloadName("resp_20260102_030405.678_REQ-00AB.body")
	if !ok || dir != "resp" || id != "REQ-00AB" || kind != "body" || ts.Year() != 2026 || ts.Nanosecond() != 678e6 {
		t.Fatalf("parse: %v %v %v %v %v", dir, ts, id, kind, ok)
	}
	if _, _, id, _, ok := parsePayloadName("req_20260102_030405.678_fe80::1.meta"); !ok || id != "fe80::1" {
		t.Fatalf("ipv6 client id: %v %v", id, ok)
	}
	for _, bad := range []string{"", "req_.meta", "req_20260102_030405.678.meta", "x_20260102_030405.678_A.meta", "req_20260102_030405.678_A.txt"} {
		if _, _, _, _, ok := parsePayloadName(bad); ok {
			t.Errorf("%q parsed unexpectedly", bad)
		}
	}
}

func TestExportCSVNeutralisesFormulas(t *testing.T) {
	s, _, _ := newTestServer(t, false)
	rec := do(t, s.Handler(), "GET", "/api/export.csv", bearer)
	body := rec.Body.String()
	if !strings.HasPrefix(body, "key,domain,ips,verdict,accepted_test,last_tested,self-signed,replaced-key") {
		t.Fatalf("unexpected header: %q", body)
	}
	if strings.Contains(body, "\n=cmd") || strings.Contains(body, ",=cmd") || !strings.Contains(body, "'=cmd") {
		t.Fatalf("formula not neutralised: %q", body)
	}
}

func TestRecentEventsValidation(t *testing.T) {
	s, _, bus := newTestServer(t, false)
	h := s.Handler()
	bus.Publish(events.TopicRequest, map[string]string{"host": "a"})

	if rec := do(t, h, "GET", "/api/events?topic=nope", bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown topic: got %d", rec.Code)
	}
	rec := do(t, h, "GET", "/api/events?topic=request&limit=10", bearer)
	var evs []events.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &evs); err != nil || len(evs) != 1 {
		t.Fatalf("recent: %v %s", err, rec.Body)
	}
}

func TestStreamDeliversEvents(t *testing.T) {
	s, _, bus := newTestServer(t, false)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/api/stream?topics=domain", nil)
	bearer(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}

	// Wait for the subscription to attach, then publish a filtered and a
	// matching event
	deadline := time.Now().Add(2 * time.Second)
	for bus.SubscriberCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	bus.Publish(events.TopicLog, "filtered out")
	bus.Publish(events.TopicDomain, map[string]string{"key": "example.com"})

	sc := bufio.NewScanner(resp.Body)
	done := make(chan string, 1)
	go func() {
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "event: ") {
				done <- line
				return
			}
		}
	}()
	select {
	case line := <-done:
		if line != "event: domain" {
			t.Fatalf("got %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event received")
	}
}
