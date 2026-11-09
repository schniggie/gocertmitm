package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/gocertmitm/internal/certificates"
)

// errDirectTunnelSkip signals that a TLS handshake should abort because the
// connection is being handled via a direct tunnel instead
var errDirectTunnelSkip = errors.New("direct tunnel mode - skipping TLS handshake")

// handshakeTimeout bounds the time spent performing the TLS handshake per
// connection so slow or silent clients cannot hold handshake goroutines open
const handshakeTimeout = 30 * time.Second

// tlsHandshakeListener performs the TLS handshake for accepted connections
// itself instead of letting the HTTP server do it. This makes handshake
// failures observable as structured data (client IP + SNI + error) rather
// than as free-form log lines that need to be parsed later.
type tlsHandshakeListener struct {
	inner  net.Listener
	server *Server
	served chan net.Conn
	done   chan struct{}
}

func newTLSHandshakeListener(inner net.Listener, server *Server) *tlsHandshakeListener {
	return &tlsHandshakeListener{
		inner:  inner,
		server: server,
		served: make(chan net.Conn, 128),
		done:   make(chan struct{}),
	}
}

// Accept hands out connections whose TLS handshake already completed. The
// handshake for the next pending connection runs in its own goroutine so a
// single slow client cannot block the accept loop.
func (h *tlsHandshakeListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn := <-h.served:
			return conn, nil
		case <-h.done:
			return nil, net.ErrClosed
		default:
		}

		rawConn, err := h.inner.Accept()
		if err != nil {
			select {
			case conn := <-h.served:
				return conn, nil
			case <-h.done:
				return nil, net.ErrClosed
			default:
			}
			return nil, err
		}

		go h.handshake(rawConn)
	}
}

// Close shuts down the underlying listener and unblocks Accept
func (h *tlsHandshakeListener) Close() error {
	select {
	case <-h.done:
		// already closed
	default:
		close(h.done)
	}
	return h.inner.Close()
}

// Addr returns the address of the underlying listener
func (h *tlsHandshakeListener) Addr() net.Addr {
	return h.inner.Addr()
}

// handshake runs the TLS handshake on a single connection. On success the
// connection is queued for the HTTP server; on failure the reason is recorded
// structurally via handleFailedTLSHandshake.
func (h *tlsHandshakeListener) handshake(rawConn net.Conn) {
	if _, ok := rawConn.(*DummyConnection); ok {
		h.enqueue(rawConn)
		return
	}

	// Clone the shared config per connection so the SNI of this handshake can
	// be captured alongside the existing GetConfigForClient logic
	base := h.server.httpsServer.TLSConfig
	origGetConfigForClient := base.GetConfigForClient
	sni := ""
	cfg := base.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = hello.ServerName
		if origGetConfigForClient != nil {
			return origGetConfigForClient(hello)
		}
		return nil, nil
	}

	tlsConn := tls.Server(rawConn, cfg)

	_ = rawConn.SetDeadline(time.Now().Add(handshakeTimeout))
	err := tlsConn.Handshake()
	_ = rawConn.SetDeadline(time.Time{})

	if err != nil {
		_ = tlsConn.Close()
		h.server.handleFailedTLSHandshake(rawConn, sni, err)
		return
	}

	h.enqueue(tlsConn)
}

// enqueue queues a fully handshaked connection for the HTTP server
func (h *tlsHandshakeListener) enqueue(conn net.Conn) {
	select {
	case h.served <- conn:
	case <-h.done:
		_ = conn.Close()
	}
}

// handleFailedTLSHandshake records a failed TLS handshake as a failed test.
// Unlike the previous log-scraping approach, the domain comes directly from
// the handshake's SNI, so failures are never attributed to unrelated domains.
func (s *Server) handleFailedTLSHandshake(rawConn net.Conn, sni string, err error) {
	clientIP := "unknown"
	if rawConn != nil && rawConn.RemoteAddr() != nil {
		if host, _, splitErr := net.SplitHostPort(rawConn.RemoteAddr().String()); splitErr == nil {
			clientIP = host
		}
	}

	reqID := s.logger.GetRequestID(clientIP, sni)

	// Direct tunnel handshakes are expected to fail - the tunnel already
	// carries the connection's traffic
	var dtErr *DirectTunnelError
	if errors.Is(err, errDirectTunnelSkip) || errors.As(err, &dtErr) {
		s.logger.DebugWithRequestIDf(reqID, "[TUNNEL-TLS-ERROR] Skipping TLS handshake failure recording for direct tunnel connection from %s", clientIP)
		return
	}

	// Without an SNI the failure cannot be attributed to a domain; do not guess
	if sni == "" {
		s.logger.Debugf("[TLS-HANDSHAKE] Handshake from %s failed before SNI was sent, not recording: %v", clientIP, err)
		return
	}

	// Skip IP addresses - they are not domains under test
	if isIPAddress(sni) {
		s.logger.Debugf("[TLS-HANDSHAKE] Handshake SNI %s is an IP address, not recording failure", sni)
		return
	}

	// Domains in direct tunnel mode never run TLS handshakes with the client
	s.directTunnelMu.Lock()
	isDirectTunnel := s.directTunnelDomains[sni]
	s.directTunnelMu.Unlock()
	if isDirectTunnel {
		s.logger.Debugf("[TUNNEL-TLS-ERROR] Ignoring TLS handshake error for domain %s as it's in direct tunnel mode", sni)
		return
	}

	// If all tests already completed without success, make sure the domain is
	// marked for direct tunnel mode and stop recording failures
	if status := s.tester.GetTestStatus(sni); status != nil && status.TestsCompleted && !status.SuccessfulTestSet {
		s.directTunnelMu.Lock()
		s.directTunnelDomains[sni] = true
		s.directTunnelMu.Unlock()
		s.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TLS-ERROR] Domain %s marked for direct tunnel mode", sni)
		return
	}

	// Record the failure only for the test type currently being exercised
	testType := s.tester.GetNextTest(sni)
	if testType == certificates.DirectTunnel {
		s.directTunnelMu.Lock()
		s.directTunnelDomains[sni] = true
		s.directTunnelMu.Unlock()
		s.logger.Debugf("[TUNNEL-TLS-ERROR] Ignoring TLS handshake error for domain %s as test type is DirectTunnel", sni)
		return
	}

	s.logger.InfoWithRequestIDf(reqID, "[TLS] Handshake error from %s for %s with test type %s",
		clientIP, sni, testType.GetTestTypeName())

	nextTest := s.RecordFailedHandshake(sni, testType, reqID)

	s.logger.InfoWithRequestIDf(reqID, "[NEXT] Moving to next test for %s: %s", sni, nextTest.GetTestTypeName())
}
