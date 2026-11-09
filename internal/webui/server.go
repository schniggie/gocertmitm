// Package webui serves the GoCertMITM web interface: a token-protected HTTP
// server exposing JSON APIs, a Server-Sent Events stream of live activity and
// an embedded single-page frontend.
//
// Security model:
//   - Every request (except static assets and the login page) requires the
//     access token, presented either as "Authorization: Bearer <token>" or via
//     an HttpOnly, SameSite=Strict session cookie set by /login.
//   - State-changing API calls additionally require the X-CertMITM-CSRF
//     header, which cannot be sent cross-origin without a CORS preflight that
//     this server never approves.
//   - With authentication disabled, requests are only accepted when the Host
//     header is an IP literal or "localhost" to defeat DNS rebinding.
//   - Captured payloads are read through os.Root so a crafted path cannot
//     escape the payload directory, and are always served as inert
//     attachments/plain text with nosniff and a restrictive CSP.
package webui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gocertmitm/internal/events"
	"github.com/gocertmitm/internal/proxy"
)

//go:embed static
var staticFS embed.FS

const (
	sessionCookie = "certmitm_session"
	csrfHeader    = "X-CertMITM-CSRF"
)

// Backend is the proxy state the UI observes and controls
type Backend interface {
	Info() proxy.Info
	Stats() proxy.Stats
	Domains() []proxy.DomainView
	Domain(key string) (proxy.DomainView, bool)
	ResetDomain(key string) bool
	DeleteDomain(key string) bool
	CACertificatePEM() []byte
	PayloadDir() string
}

// Logger is the subset of the application logger used by the UI
type Logger interface {
	Infof(format string, v ...interface{})
	Errorf(format string, v ...interface{})
}

// Config configures the web UI server
type Config struct {
	Addr    string
	Token   string // access token; required unless NoAuth is set
	NoAuth  bool   // disable authentication (loopback/IP-literal Host only)
	Backend Backend
	Bus     *events.Bus
	Logger  Logger
}

// Server is the web UI HTTP server
type Server struct {
	cfg    Config
	http   *http.Server
	static fs.FS
}

// GenerateToken returns a random 128-bit hex access token
func GenerateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// New creates a web UI server
func New(cfg Config) (*Server, error) {
	if cfg.Backend == nil || cfg.Bus == nil || cfg.Logger == nil {
		return nil, errors.New("webui: backend, bus and logger are required")
	}
	if !cfg.NoAuth && len(cfg.Token) < 16 {
		return nil, errors.New("webui: access token must be at least 16 characters")
	}

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, static: static}
	s.http = &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second, // lifted per-request for the event stream
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return s, nil
}

// ListenAndServe starts serving; it returns http.ErrServerClosed on Shutdown
func (s *Server) ListenAndServe() error {
	return s.http.ListenAndServe()
}

// Serve serves on an existing listener
func (s *Server) Serve(l net.Listener) error {
	return s.http.Serve(l)
}

// Shutdown gracefully stops the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// Handler returns the fully wrapped HTTP handler
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.static)))
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// Authenticated
	mux.Handle("GET /{$}", s.requireAuth(http.HandlerFunc(s.handleIndex)))
	api := http.NewServeMux()
	api.HandleFunc("GET /api/info", s.handleInfo)
	api.HandleFunc("GET /api/stats", s.handleStats)
	api.HandleFunc("GET /api/domains", s.handleDomains)
	api.HandleFunc("GET /api/domains/{key}", s.handleDomain)
	api.HandleFunc("POST /api/domains/{key}/reset", s.handleResetDomain)
	api.HandleFunc("DELETE /api/domains/{key}", s.handleDeleteDomain)
	api.HandleFunc("GET /api/events", s.handleRecentEvents)
	api.HandleFunc("GET /api/stream", s.handleStream)
	api.HandleFunc("GET /api/payloads", s.handlePayloadHosts)
	api.HandleFunc("GET /api/payloads/{host}", s.handlePayloadExchanges)
	api.HandleFunc("GET /api/payloads/{host}/{file}", s.handlePayloadFile)
	api.HandleFunc("GET /api/ca.pem", s.handleCA)
	api.HandleFunc("GET /api/export.json", s.handleExportJSON)
	api.HandleFunc("GET /api/export.csv", s.handleExportCSV)
	mux.Handle("/api/", s.requireAuth(s.requireCSRF(api)))

	return s.securityHeaders(s.hostGuard(mux))
}

// securityHeaders sets defensive headers on every response
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// hostGuard rejects DNS-rebinding attempts when authentication is disabled
func (s *Server) hostGuard(next http.Handler) http.Handler {
	if !s.cfg.NoAuth {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if net.ParseIP(host) == nil && !strings.EqualFold(host, "localhost") {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authenticated reports whether the request carries a valid token
func (s *Server) authenticated(r *http.Request) bool {
	if s.cfg.NoAuth {
		return true
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return s.tokenMatches(strings.TrimPrefix(auth, "Bearer "))
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		return s.tokenMatches(c.Value)
	}
	return false
}

func (s *Server) tokenMatches(candidate string) bool {
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(s.cfg.Token)) == 1
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow a one-shot ?token= link (as printed at startup) to establish
		// a session, then redirect so the token does not linger in the URL
		if tok := r.URL.Query().Get("token"); tok != "" && r.Method == http.MethodGet && r.URL.Path == "/" {
			if s.tokenMatches(tok) {
				s.setSession(w, r)
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if s.authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

// requireCSRF demands a custom header on state-changing requests
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.Header.Get(csrfHeader) != "1" || !sameOrigin(r) {
				writeJSONError(w, http.StatusForbidden, "missing or invalid CSRF header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin rejects requests whose Origin header names a different host
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	o := strings.TrimPrefix(strings.TrimPrefix(origin, "http://"), "https://")
	return strings.EqualFold(o, r.Host)
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    s.cfg.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.authenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.serveStatic(w, r, "login.html")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-origin login rejected", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.NoAuth || s.tokenMatches(strings.TrimSpace(r.PostForm.Get("token"))) {
		if !s.cfg.NoAuth {
			s.setSession(w, r)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.cfg.Logger.Infof("[WEBUI] Failed login attempt from %s", r.RemoteAddr)
	time.Sleep(500 * time.Millisecond) // blunt online guessing
	http.Redirect(w, r, "/login?failed=1", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-origin logout rejected", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.serveStatic(w, r, "index.html")
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request, name string) {
	data, err := fs.ReadFile(s.static, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// writeJSON encodes v as the response body
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		// Headers are already sent; nothing more to do
		return
	}
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := s.cfg.Backend.Info()
	writeJSON(w, http.StatusOK, struct {
		proxy.Info
		AuthEnabled bool `json:"auth_enabled"`
	}{info, !s.cfg.NoAuth})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st := s.cfg.Backend.Stats()
	writeJSON(w, http.StatusOK, struct {
		proxy.Stats
		Now         time.Time `json:"now"`
		Subscribers int       `json:"ui_subscribers"`
	}{st, time.Now(), s.cfg.Bus.SubscriberCount()})
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.cfg.Backend.Domains())
}

func (s *Server) handleDomain(w http.ResponseWriter, r *http.Request) {
	view, ok := s.cfg.Backend.Domain(r.PathValue("key"))
	if !ok {
		writeJSONError(w, http.StatusNotFound, "unknown domain")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleResetDomain(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !s.cfg.Backend.ResetDomain(key) {
		writeJSONError(w, http.StatusNotFound, "unknown domain")
		return
	}
	s.cfg.Logger.Infof("[WEBUI] %s reset test state for %s", r.RemoteAddr, key)
	view, _ := s.cfg.Backend.Domain(key)
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !s.cfg.Backend.DeleteDomain(key) {
		writeJSONError(w, http.StatusNotFound, "unknown domain")
		return
	}
	s.cfg.Logger.Infof("[WEBUI] %s deleted test state for %s", r.RemoteAddr, key)
	w.WriteHeader(http.StatusNoContent)
}

var knownTopics = map[string]bool{
	events.TopicDomain:    true,
	events.TopicRequest:   true,
	events.TopicHandshake: true,
	events.TopicLog:       true,
}

func (s *Server) handleRecentEvents(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Query().Get("topic")
	if !knownTopics[topic] {
		writeJSONError(w, http.StatusBadRequest, "unknown topic")
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &limit); err != nil || limit < 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid limit")
			return
		}
	}
	writeJSON(w, http.StatusOK, s.cfg.Bus.Recent(topic, limit))
}

// handleStream streams live events as Server-Sent Events. Clients that fall
// behind are disconnected with a "resync" event and are expected to reload
// their snapshots and reconnect.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	// The server-wide read/write timeouts would otherwise cut the long-lived
	// stream (the read deadline also governs net/http's background read,
	// whose timeout cancels the request context)
	rc := http.NewResponseController(w)
	for _, clearDeadline := range []func(time.Time) error{rc.SetWriteDeadline, rc.SetReadDeadline} {
		if err := clearDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
			s.cfg.Logger.Errorf("[WEBUI] Failed to clear stream deadline: %v", err)
		}
	}

	topics := knownTopics
	if q := r.URL.Query().Get("topics"); q != "" {
		topics = make(map[string]bool)
		for _, t := range strings.Split(q, ",") {
			if knownTopics[t] {
				topics[t] = true
			}
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 3000\n\n")
	if err := rc.Flush(); err != nil {
		return
	}

	sub := s.cfg.Bus.Subscribe()
	defer sub.Close()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
		case ev, ok := <-sub.C:
			if !ok {
				fmt.Fprint(w, "event: resync\ndata: {}\n\n")
				_ = rc.Flush()
				return
			}
			if !topics[ev.Topic] {
				continue
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", ev.ID, ev.Topic, data); err != nil {
				return
			}
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	pemBytes := s.cfg.Backend.CACertificatePEM()
	if len(pemBytes) == 0 {
		writeJSONError(w, http.StatusNotFound, "no CA certificate")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="certmitm-ca.pem"`)
	_, _ = w.Write(pemBytes)
}
