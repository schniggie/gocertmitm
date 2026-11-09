package proxy

import (
	"io"
	"net"
	"sync"
	"time"
)

// copyData copies data between two connections with an inactivity timeout
// It's used for regular MITM connections
// Returns an error if the connection was reset or closed unexpectedly
func copyData(dst, src net.Conn, reqID string, domain string, server *Server) error {
	defer dst.Close()
	defer src.Close()

	// Use a larger buffer for better performance
	buf := make([]byte, 64*1024)

	// Create a channel to signal activity
	activity := make(chan struct{}, 1)

	// Create a channel to signal when the connection should be closed due to inactivity
	closeConn := make(chan struct{}, 1)

	// Variable to store the last error encountered
	var lastErr error

	// Start a goroutine to monitor for inactivity
	go func() {
		inactivityTimeout := 10 * time.Second
		timer := time.NewTimer(inactivityTimeout)
		defer timer.Stop()

		for {
			select {
			case <-activity:
				// Reset the timer when there's activity
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(inactivityTimeout)
			case <-timer.C:
				// Timeout occurred - close the idle connection. An inactivity
				// timeout is not evidence that a test type failed, so it must
				// not be recorded as one
				if server != nil && domain != "" && reqID != "" {
					server.logger.DebugWithRequestIDf(reqID, "[TIMEOUT] No activity for %s on MITM connection for %s - closing connection",
						inactivityTimeout, domain)
				}

				closeConn <- struct{}{}
				return
			}
		}
	}()

	// Copy loop with activity signaling and timeout checking
	for {
		// Check if we should close due to inactivity
		select {
		case <-closeConn:
			return lastErr
		default:
			// Continue with normal operation
		}

		// Set a read deadline to ensure we can check for the close signal periodically
		src.SetReadDeadline(time.Now().Add(1 * time.Second))

		// Read from source
		n, err := src.Read(buf)
		if n > 0 {
			// Signal activity
			select {
			case activity <- struct{}{}:
			default:
				// Channel buffer is full, which is fine
			}

			// Write to destination
			_, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				// Write error
				lastErr = writeErr
				return writeErr
			}
		}

		if err != nil {
			if err == io.EOF {
				// Normal end of connection
				return nil
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// This is just our read deadline - continue the loop
				continue
			} else {
				// Other read error
				lastErr = err
				return err
			}
		}
	}
}

// Note: We're using the copyData function instead of copyBuffer

// ConnectionTracker tracks connections
type ConnectionTracker struct {
	connections map[string]int
	mu          sync.Mutex
}

// NewConnectionTracker creates a new connection tracker
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]int),
	}
}

// Track tracks a connection
func (c *ConnectionTracker) Track(clientIP string, isConnect bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if isConnect {
		c.connections[clientIP]++
	} else {
		c.connections[clientIP]--
		if c.connections[clientIP] <= 0 {
			delete(c.connections, clientIP)
		}
	}
}

// Count returns the number of connections for a client
func (c *ConnectionTracker) Count(clientIP string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.connections[clientIP]
}

// GetAll returns all connections
func (c *ConnectionTracker) GetAll() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create a copy of the connections map
	connections := make(map[string]int, len(c.connections))
	for k, v := range c.connections {
		connections[k] = v
	}

	return connections
}
