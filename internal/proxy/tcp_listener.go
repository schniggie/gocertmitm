package proxy

import (
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DebugListener is a wrapper around net.Listener that logs connections as soon as they're accepted
type DebugListener struct {
	net.Listener
	server *Server // Reference to the server instance
}

// NewDebugListener creates a new DebugListener
func NewDebugListener(addr string, server *Server) (*DebugListener, error) {
	// Create a TCP listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &DebugListener{
		Listener: listener,
		server:   server,
	}, nil
}

// NewDebugConnection creates a new DebugConnection
func NewDebugConnection(conn net.Conn, server *Server, domain, clientIP, reqID string) *DebugConnection {
	return &DebugConnection{
		Conn:     conn,
		server:   server,
		domain:   domain,
		clientIP: clientIP,
		reqID:    reqID,
	}
}

// Accept accepts a connection and logs it immediately
func (l *DebugListener) Accept() (net.Conn, error) {
	// Accept the connection
	conn, err := l.Listener.Accept()
	if err != nil {
		l.server.logger.Debugf("[TCP-ACCEPT] Error accepting connection: %v", err)
		return nil, err
	}

	// Log the connection immediately
	l.server.logger.Debugf("[TCP-ACCEPT] New TCP connection accepted from %s to %s",
		conn.RemoteAddr(), conn.LocalAddr())

	// Extract client IP for logging
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// Try to get the original destination using SO_ORIGINAL_DST
	var origDestIP string
	var origDestPort int
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		origDest, origDestErr := GetOriginalDst(tcpConn)
		if origDestErr != nil {
			l.server.logger.Debugf("[TCP-ACCEPT] Failed to get original destination: %v", origDestErr)
		} else {
			origDestIP = origDest.IPString
			origDestPort = origDest.Port

			l.server.logger.Debugf("[TCP-ACCEPT] Original destination: %s for connection from %s", origDest.HostPort, conn.RemoteAddr())

			// Check if this IP is already marked for direct tunnel mode
			if l.server != nil {
				l.server.directTunnelMu.Lock()
				directTunnel := l.server.directTunnelDomains[origDestIP]

				// Check if we have a domain for this IP in the ipToDomain map
				if !directTunnel && l.server.tester != nil {
					domain := l.server.tester.GetDomainByIP(origDestIP)
					if domain != "" {
						directTunnel = l.server.directTunnelDomains[domain]

						// If the domain is marked for direct tunnel, also mark the IP
						if directTunnel {
							l.server.directTunnelDomains[origDestIP] = true
							l.server.logger.Debugf("[TCP-ACCEPT] Marking IP %s for direct tunnel based on domain %s", origDestIP, domain)
						}
					}
				}
				l.server.directTunnelMu.Unlock()

				if directTunnel {
					l.server.logger.Debugf("[TCP-ACCEPT] Original destination IP %s is marked for direct tunnel mode", origDestIP)

					destAddr := net.JoinHostPort(origDestIP, strconv.Itoa(origDestPort))
					reqID := l.server.logger.GetRequestID(clientIP, origDestIP)

					// Handle the connection directly and do not return it to
					// the HTTP server; the target dial happens in background
					return startTCPDirectTunnel(l.server, conn, destAddr, reqID), nil
				}
			}
		}
	} else {
		l.server.logger.Debugf("[TCP-ACCEPT] Connection is not a TCP connection, cannot get original destination")
	}

	// Create the debug connection with default values
	debugConn := &DebugConnection{
		Conn:     conn,
		server:   l.server,
		clientIP: clientIP,
	}

	// Set the original destination on the debug connection if we have it
	if origDestIP != "" {
		debugConn.SetOriginalDestination(origDestIP, origDestPort)
	}

	return debugConn, nil
}

// startTCPDirectTunnel splices the client connection to destAddr and returns
// a dummy connection so the HTTP server ignores this connection. The target
// dial and the passthrough run in a goroutine so callers never block on the
// remote endpoint.
func startTCPDirectTunnel(server *Server, clientConn net.Conn, destAddr, reqID string) *DummyConnection {
	server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Starting direct TCP tunnel from %s to %s", clientConn.RemoteAddr(), destAddr)
	server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Pure passthrough mode - no data inspection or modification")

	go func() {
		defer clientConn.Close()

		targetConn, err := net.DialTimeout("tcp", destAddr, 30*time.Second)
		if err != nil {
			server.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to connect to target %s: %v", destAddr, err)
			return
		}
		defer targetConn.Close()

		server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Connected to target %s for direct TCP tunnel", destAddr)

		// Bidirectional copy; wait for both directions to finish
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			n, err := io.Copy(targetConn, clientConn)
			if err != nil && err != io.EOF {
				server.logger.DebugWithRequestIDf(reqID, "[TCP-COPY] Error copying from client to target: %v", err)
			} else if n > 0 {
				server.logger.DebugWithRequestIDf(reqID, "[TCP-COPY] Copied %d bytes from client to target", n)
			}
		}()

		go func() {
			defer wg.Done()
			n, err := io.Copy(clientConn, targetConn)
			if err != nil && err != io.EOF {
				server.logger.DebugWithRequestIDf(reqID, "[TCP-COPY] Error copying from target to client: %v", err)
			} else if n > 0 {
				server.logger.DebugWithRequestIDf(reqID, "[TCP-COPY] Copied %d bytes from target to client", n)
			}
		}()

		wg.Wait()

		server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Direct TCP tunnel closed between %s and %s", clientConn.RemoteAddr(), destAddr)
	}()

	return &DummyConnection{
		clientAddr: clientConn.RemoteAddr(),
		localAddr:  clientConn.LocalAddr(),
	}
}

// DebugConnection is a wrapper around net.Conn that logs read/write operations
type DebugConnection struct {
	net.Conn
	server       *Server // Reference to the server instance
	domain       string  // Domain being accessed
	clientIP     string  // Client IP address
	reqID        string  // Request ID for logging
	directTunnel bool    // Flag indicating if this connection should use direct tunnel mode
	origDestIP   string  // Original destination IP address
	origDestPort int     // Original destination port
}

// Read reads data from the connection and logs it
func (c *DebugConnection) Read(b []byte) (n int, err error) {
	// If this connection is marked for direct tunnel mode, we should not log or process the data
	// This is to prevent any interference with the direct tunnel
	if c.directTunnel {
		// Just pass through the read without any logging or processing
		return c.Conn.Read(b)
	}

	n, err = c.Conn.Read(b)
	if err != nil && err != net.ErrClosed {
		// Use reqID if available, otherwise use a placeholder
		reqID := c.reqID
		if reqID == "" {
			reqID = "NO-REQ-ID"
		}

		c.server.logger.DebugWithRequestIDf(reqID, "[TCP-READ] Error reading from %s: %v", c.Conn.RemoteAddr(), err)

		// Check for connection reset by peer or broken pipe
		if strings.Contains(err.Error(), "connection reset by peer") ||
			strings.Contains(err.Error(), "broken pipe") {
			// Log the connection reset
			c.server.logger.DebugWithRequestIDf(reqID, "[TCP-READ] Connection reset detected for %s - this should be treated as a test failure",
				c.Conn.RemoteAddr())

			// If we have a server reference and domain, call HandleConnectionReset
			if c.server != nil && c.domain != "" {
				c.server.logger.DebugWithRequestIDf(reqID, "[TCP-READ] Calling HandleConnectionReset for domain %s from client %s",
					c.domain, c.clientIP)
				c.server.HandleConnectionReset(c.clientIP, c.domain)
			} else {
				c.server.logger.DebugWithRequestIDf(reqID, "[TCP-READ] Cannot call HandleConnectionReset: server=%v, domain=%s",
					c.server != nil, c.domain)
			}
		}
	} else if n > 0 {
		if c.reqID != "" {
			c.server.logger.DebugWithRequestIDf(c.reqID, "[TCP-READ] Read %d bytes from %s", n, c.Conn.RemoteAddr())
		} else {
			c.server.logger.Debugf("[TCP-READ] Read %d bytes from %s", n, c.Conn.RemoteAddr())
		}
	}
	return
}

// Write writes data to the connection and logs it
func (c *DebugConnection) Write(b []byte) (n int, err error) {
	// If this connection is marked for direct tunnel mode, we should not log or process the data
	// This is to prevent any interference with the direct tunnel
	if c.directTunnel {
		// Just pass through the write without any logging or processing
		return c.Conn.Write(b)
	}

	// Use reqID if available, otherwise use a placeholder
	reqID := c.reqID
	if reqID == "" {
		reqID = "NO-REQ-ID"
	}

	// Log the data being written for debugging
	if len(b) <= 20 {
		// For small writes, log the actual bytes
		c.server.logger.DebugWithRequestIDf(reqID, "[TCP-WRITE-DATA] Writing %d bytes to %s: %v", len(b), c.Conn.RemoteAddr(), b)

		// Also try to interpret as ASCII
		asciiStr := ""
		for _, byt := range b {
			if byt >= 32 && byt <= 126 {
				asciiStr += string(byt)
			} else {
				asciiStr += "."
			}
		}
		c.server.logger.DebugWithRequestIDf(reqID, "[TCP-WRITE-ASCII] ASCII interpretation: %s", asciiStr)
	}

	n, err = c.Conn.Write(b)
	if err != nil {
		c.server.logger.DebugWithRequestIDf(reqID, "[TCP-WRITE] Error writing to %s: %v", c.Conn.RemoteAddr(), err)

		// Check for connection reset by peer or broken pipe
		if strings.Contains(err.Error(), "connection reset by peer") ||
			strings.Contains(err.Error(), "broken pipe") ||
			strings.Contains(err.Error(), "write: broken pipe") {
			// Log the connection reset
			c.server.logger.DebugWithRequestIDf(reqID, "[TCP-WRITE] Connection reset detected for %s - this should be treated as a test failure",
				c.Conn.RemoteAddr())

			// If we have a server reference and domain, call HandleConnectionReset
			if c.server != nil && c.domain != "" {
				c.server.logger.DebugWithRequestIDf(reqID, "[TCP-WRITE] Calling HandleConnectionReset for domain %s from client %s",
					c.domain, c.clientIP)
				c.server.HandleConnectionReset(c.clientIP, c.domain)
			} else {
				c.server.logger.DebugWithRequestIDf(reqID, "[TCP-WRITE] Cannot call HandleConnectionReset: server=%v, domain=%s",
					c.server != nil, c.domain)
			}
		}
	} else if n > 0 {
		c.server.logger.DebugWithRequestIDf(reqID, "[TCP-WRITE] Wrote %d bytes to %s", n, c.Conn.RemoteAddr())
	}
	return
}

// Close closes the connection and logs it
func (c *DebugConnection) Close() error {
	// If this connection is marked for direct tunnel mode, we should not log
	// This is to prevent any interference with the direct tunnel
	if c.directTunnel {
		// Just pass through the close without any logging
		return c.Conn.Close()
	}

	// Use reqID if available, otherwise use a placeholder
	reqID := c.reqID
	if reqID == "" {
		reqID = "NO-REQ-ID"
	}

	c.server.logger.DebugWithRequestIDf(reqID, "[TCP-CLOSE] Closing connection to %s", c.Conn.RemoteAddr())
	return c.Conn.Close()
}

// SetDeadline sets the read and write deadlines
func (c *DebugConnection) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (c *DebugConnection) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *DebugConnection) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// SetDomain sets the domain for this connection
func (c *DebugConnection) SetDomain(domain string) {
	if domain != "" && c.domain != domain {
		// Use reqID if available, otherwise use a placeholder
		reqID := c.reqID
		if reqID == "" {
			reqID = "NO-REQ-ID"
		}

		c.server.logger.DebugWithRequestIDf(reqID, "[TCP-DOMAIN] Setting domain for connection %s to %s", c.Conn.RemoteAddr(), domain)
		c.domain = domain
	}
}

// SetClientIP sets the client IP for this connection
func (c *DebugConnection) SetClientIP(clientIP string) {
	if clientIP != "" && c.clientIP != clientIP {
		// Use reqID if available, otherwise use a placeholder
		reqID := c.reqID
		if reqID == "" {
			reqID = "NO-REQ-ID"
		}

		c.server.logger.DebugWithRequestIDf(reqID, "[TCP-CLIENT] Setting client IP for connection %s to %s", c.Conn.RemoteAddr(), clientIP)
		c.clientIP = clientIP
	}
}

// SetRequestID sets the request ID for this connection
func (c *DebugConnection) SetRequestID(reqID string) {
	if reqID != "" && c.reqID != reqID {
		// For this method, we can't use the request ID in the log message since we're setting it
		c.server.logger.Debugf("[TCP-REQID] Setting request ID for connection %s to %s", c.Conn.RemoteAddr(), reqID)
		c.reqID = reqID
	}
}

// SetDirectTunnel marks this connection for direct tunnel mode
func (c *DebugConnection) SetDirectTunnel(directTunnel bool) {
	if c.directTunnel != directTunnel {
		// Use reqID if available, otherwise use a placeholder
		reqID := c.reqID
		if reqID == "" {
			reqID = "NO-REQ-ID"
		}

		c.server.logger.DebugWithRequestIDf(reqID, "[TCP-TUNNEL] Setting direct tunnel mode for connection %s to %v", c.Conn.RemoteAddr(), directTunnel)
		c.directTunnel = directTunnel
	}
}

// IsDirectTunnel returns whether this connection should use direct tunnel mode
func (c *DebugConnection) IsDirectTunnel() bool {
	return c.directTunnel
}

// SetOriginalDestination sets the original destination IP and port for this connection
func (c *DebugConnection) SetOriginalDestination(ip string, port int) {
	c.origDestIP = ip
	c.origDestPort = port

	// Use reqID if available, otherwise use a placeholder
	reqID := c.reqID
	if reqID == "" {
		reqID = "NO-REQ-ID"
	}

	c.server.logger.DebugWithRequestIDf(reqID, "[TCP-ORIGDST] Setting original destination for connection %s to %s:%d",
		c.Conn.RemoteAddr(), ip, port)
}

// GetOriginalDestination returns the original destination IP and port for this connection
func (c *DebugConnection) GetOriginalDestination() (string, int) {
	return c.origDestIP, c.origDestPort
}

// DirectTunnelListener is a wrapper around net.Listener that handles direct tunnel connections
// It checks if the original destination IP is marked for direct tunnel mode and handles it directly
type DirectTunnelListener struct {
	net.Listener
	server *Server // Reference to the server instance
}

// Accept accepts a connection and checks if it should be handled as a direct tunnel
func (l *DirectTunnelListener) Accept() (net.Conn, error) {
	// Accept the connection from the underlying listener
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER-ACCEPT] Accepted connection from %s to %s",
		conn.RemoteAddr(), conn.LocalAddr())

	// Check if this is a DebugConnection
	debugConn, ok := conn.(*DebugConnection)
	if !ok {
		// If it's not a DebugConnection, just return it as-is
		l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER-ACCEPT] Connection is not a DebugConnection, returning as-is")
		return conn, nil
	}

	l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER-ACCEPT] Connection is a DebugConnection")

	// Get the original destination IP and port
	origDestIP, origDestPort := debugConn.GetOriginalDestination()
	l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER-ACCEPT] Original destination: %s:%d",
		origDestIP, origDestPort)

	if origDestIP == "" {
		// If we don't have an original destination, just return the connection as-is
		l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER-ACCEPT] No original destination, returning connection as-is")
		return conn, nil
	}

	// Check if this IP is already marked for direct tunnel mode
	l.server.directTunnelMu.Lock()
	directTunnel := l.server.directTunnelDomains[origDestIP]

	// Log the direct tunnel domains map for debugging
	l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER] Checking if IP %s is marked for direct tunnel: %v",
		origDestIP, directTunnel)
	l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER] Current directTunnelDomains map contents:")
	for domain := range l.server.directTunnelDomains {
		l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER]   %s", domain)
	}

	// If the IP is not marked for direct tunnel, check if we have a domain for this connection
	// that is marked for direct tunnel
	if !directTunnel && debugConn.domain != "" {
		directTunnel = l.server.directTunnelDomains[debugConn.domain]
		l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER] Checking if domain %s is marked for direct tunnel: %v",
			debugConn.domain, directTunnel)

		// If the domain is marked for direct tunnel, also mark the IP for future connections
		if directTunnel && origDestIP != "" {
			l.server.directTunnelDomains[origDestIP] = true
			l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER] Marking IP %s for direct tunnel mode based on domain %s",
				origDestIP, debugConn.domain)
		}
	}
	l.server.directTunnelMu.Unlock()

	if directTunnel {
		// This connection should use direct tunnel mode
		l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER] Original destination IP %s is marked for direct tunnel mode", origDestIP)
		l.server.logger.Debugf("[DIRECT-TUNNEL-LISTENER] Using direct TCP tunnel for connection from %s to %s:%d",
			debugConn.clientIP, origDestIP, origDestPort)

		// Get a request ID for this connection
		reqID := l.server.logger.GetRequestID(debugConn.clientIP, origDestIP)

		// Log that we're starting a direct TCP tunnel
		l.server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TCP-DIRECT] Starting direct TCP tunnel from %s to %s:%d",
			debugConn.clientIP, origDestIP, origDestPort)

		// Hand the connection to the shared direct tunnel helper; the dial
		// and passthrough run in background so the accept loop is not blocked
		return startTCPDirectTunnel(l.server, conn, net.JoinHostPort(origDestIP, strconv.Itoa(origDestPort)), reqID), nil
	}
	// If this connection is not marked for direct tunnel mode, just return it as-is
	return conn, nil
}

// DummyConnection is a dummy connection that does nothing
// It's used to return a connection from Accept when we've already handled the connection
// This prevents the HTTP server from exiting with an error
type DummyConnection struct {
	clientAddr net.Addr
	localAddr  net.Addr
}

// Read implements the net.Conn interface
func (c *DummyConnection) Read(b []byte) (n int, err error) {
	// Always return EOF to indicate that the connection is closed
	return 0, io.EOF
}

// Write implements the net.Conn interface
func (c *DummyConnection) Write(b []byte) (n int, err error) {
	// Always return EOF to indicate that the connection is closed
	return 0, io.EOF
}

// Close implements the net.Conn interface
func (c *DummyConnection) Close() error {
	// Do nothing
	return nil
}

// LocalAddr implements the net.Conn interface
func (c *DummyConnection) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr implements the net.Conn interface
func (c *DummyConnection) RemoteAddr() net.Addr {
	return c.clientAddr
}

// SetDeadline implements the net.Conn interface
func (c *DummyConnection) SetDeadline(t time.Time) error {
	// Do nothing
	return nil
}

// SetReadDeadline implements the net.Conn interface
func (c *DummyConnection) SetReadDeadline(t time.Time) error {
	// Do nothing
	return nil
}

// SetWriteDeadline implements the net.Conn interface
func (c *DummyConnection) SetWriteDeadline(t time.Time) error {
	// Do nothing
	return nil
}
