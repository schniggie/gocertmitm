package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	// connectPeekTimeout bounds how long a CONNECT tunnel waits for the
	// client's first byte. Server-speaks-first protocols never send one, so
	// they fall back to a raw tunnel once it expires.
	connectPeekTimeout = 5 * time.Second

	// connectDialTimeout bounds dialing the target of a raw CONNECT tunnel
	connectDialTimeout = 10 * time.Second

	// tlsRecordTypeHandshake is the first byte of a TLS ClientHello record
	tlsRecordTypeHandshake = 0x16
)

// bufferedConn replays bytes already read into a bufio.Reader (by the HTTP
// server or by peeking) before reading from the underlying connection
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// interceptConnect handles an explicit-proxy CONNECT tunnel that should be
// intercepted. TLS tunnels are handed to the same handshake listener that
// serves transparently redirected connections, so certificate selection,
// failure recording, request relaying and payload capture behave exactly as
// in transparent mode. Anything that is not TLS is spliced to the target.
func (s *Server) interceptConnect(w http.ResponseWriter, r *http.Request, reqID, clientIP string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.logger.ErrorWithRequestIDf(reqID, "[CONNECT] Hijacking not supported for client %s", clientIP)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, brw, err := hijacker.Hijack()
	if err != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[CONNECT] Failed to hijack connection from %s: %v", clientIP, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// The HTTP server's deadlines no longer apply to the tunnel
	_ = clientConn.SetDeadline(time.Time{})

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		s.logger.DebugWithRequestIDf(reqID, "[CONNECT] Failed to confirm tunnel to %s: %v", clientIP, err)
		_ = clientConn.Close()
		return
	}

	// Peek at the first byte the client sends inside the tunnel
	_ = clientConn.SetReadDeadline(time.Now().Add(connectPeekTimeout))
	first, peekErr := brw.Reader.Peek(1)
	_ = clientConn.SetReadDeadline(time.Time{})

	conn := &bufferedConn{Conn: clientConn, r: brw.Reader}

	switch {
	case peekErr == nil && first[0] == tlsRecordTypeHandshake:
		tl := s.tlsListener.Load()
		if tl == nil {
			s.logger.ErrorWithRequestIDf(reqID, "[CONNECT] HTTPS listener not running; cannot intercept %s", r.Host)
			_ = conn.Close()
			return
		}
		s.logger.InfoWithRequestIDf(reqID, "[CONNECT] Intercepting TLS tunnel from %s to %s", clientIP, r.Host)
		tl.Inject(conn)

	case peekErr == nil || errors.Is(peekErr, os.ErrDeadlineExceeded):
		// Plain-text protocol, or one where the server speaks first
		s.logger.InfoWithRequestIDf(reqID, "[CONNECT] Tunnel from %s to %s is not TLS; relaying without interception", clientIP, r.Host)
		go s.spliceToTarget(conn, r.Host, reqID)

	default:
		s.logger.DebugWithRequestIDf(reqID, "[CONNECT] Client %s closed tunnel to %s before sending data: %v", clientIP, r.Host, peekErr)
		_ = conn.Close()
	}
}

// spliceToTarget relays a tunnel byte-for-byte to its target
func (s *Server) spliceToTarget(client net.Conn, target, reqID string) {
	defer client.Close()

	upstream, err := net.DialTimeout("tcp", target, connectDialTimeout)
	if err != nil {
		s.logger.ErrorWithRequestIDf(reqID, "[CONNECT] Failed to connect to %s: %v", target, err)
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Propagate EOF so the other direction can finish cleanly
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	<-done
	<-done
}
