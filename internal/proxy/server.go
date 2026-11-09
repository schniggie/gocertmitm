package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/events"
	"github.com/gocertmitm/internal/logging"
)

// DirectTunnelError is a special error type to indicate that a direct tunnel should be used
type DirectTunnelError struct {
	Domain string
}

// Error implements the error interface
func (e *DirectTunnelError) Error() string {
	return fmt.Sprintf("direct tunnel requested for %s", e.Domain)
}

// Server represents a proxy server
type Server struct {
	httpAddr            string
	httpsAddr           string
	certManager         *certificates.Manager
	logger              *logging.Logger
	payloadLogger       *logging.PayloadLogger
	httpServer          *http.Server
	httpsServer         *http.Server
	testType            certificates.TestType
	connections         map[string]int
	connectionMu        sync.Mutex
	savePayloads        bool
	tester              *Tester
	autoTest            bool                                      // Whether to automatically test all methods
	failedHandshakes    map[string]map[certificates.TestType]bool // Track failed handshakes
	handshakesMu        sync.Mutex                                // Mutex for failedHandshakes
	directTunnelDomains map[string]bool                           // Domains that should use direct tunnel
	directTunnelMu      sync.Mutex                                // Mutex for directTunnelDomains
	clientDestinations  map[string]string                         // Map client IP to destination host:port
	clientDestMu        sync.Mutex                                // Mutex for clientDestinations
	recentDomains       []string                                  // Track recently accessed domains
	recentDomainsMu     sync.Mutex                                // Mutex for recentDomains
	regularTransport    *http.Transport                           // Shared transport for regular HTTP requests
	payloadDir          string                                    // Directory payloads are written to
	startTime           time.Time                                 // When the server was created
	events              *events.Bus                               // Optional observer bus (web UI)
	stats               serverCounters                            // Monotonic counters for observers
	tlsListener         atomic.Pointer[tlsHandshakeListener]      // HTTPS handshake listener; CONNECT tunnels are injected here
}

// NewServer creates a new proxy server
func NewServer(httpAddr, httpsAddr string, certManager *certificates.Manager, logger *logging.Logger, retryPeriod ...time.Duration) (*Server, error) {
	// Create payload logger
	payloadLogger, err := logging.NewPayloadLogger("./payloads")
	if err != nil {
		return nil, fmt.Errorf("failed to create payload logger: %v", err)
	}

	// Create tester with default test type (will be updated later)
	// If retryPeriod is provided, use it, otherwise use default (1 hour)
	// Default maxAttempts is 1
	var tester *Tester
	if len(retryPeriod) > 0 {
		tester = NewTesterWithRetryPeriod(logger, certificates.SelfSigned, retryPeriod[0], 1)
	} else {
		tester = NewTester(logger, certificates.SelfSigned)
	}

	server := &Server{
		httpAddr:            httpAddr,
		httpsAddr:           httpsAddr,
		certManager:         certManager,
		logger:              logger,
		payloadLogger:       payloadLogger,
		testType:            certificates.SelfSigned, // Default test type
		connections:         make(map[string]int),
		savePayloads:        true, // Enable payload saving by default
		tester:              tester,
		autoTest:            true, // Enable automatic testing by default
		failedHandshakes:    make(map[string]map[certificates.TestType]bool),
		regularTransport:    newRegularTransport(),
		directTunnelDomains: make(map[string]bool),
		clientDestinations:  make(map[string]string), // Track client IP to destination mapping
		recentDomains:       make([]string, 0, 10),   // Track up to 10 recent domains
		payloadDir:          "./payloads",
		startTime:           time.Now(),
	}

	// Create HTTP server
	httpHandler := http.HandlerFunc(server.handleHTTP)
	server.httpServer = &http.Server{
		Addr:         httpAddr,
		Handler:      httpHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Create HTTPS server
	httpsHandler := http.HandlerFunc(server.handleHTTPS)
	server.httpsServer = &http.Server{
		Addr:    httpsAddr,
		Handler: httpsHandler,
		TLSConfig: &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				// Get the server name from the client hello
				serverName := hello.ServerName
				if serverName == "" {
					serverName = "default.example.com"
				}

				// Get client IP (for logging)
				if hello.Conn != nil {
					clientIP, _, _ := net.SplitHostPort(hello.Conn.RemoteAddr().String())

					// Get a request ID for this connection
					reqID := server.logger.GetRequestID(clientIP, serverName)

					server.logger.DebugWithRequestIDf(reqID, "[TLS-CONFIG] Client IP: %s, Server Name: %s", clientIP, serverName)
				}

				// Check if this is a DebugConnection
				if debugConn, ok := hello.Conn.(*DebugConnection); ok {
					// Get the request ID if it exists, or create one
					reqID := debugConn.reqID
					if reqID == "" {
						clientIP, _, _ := net.SplitHostPort(hello.Conn.RemoteAddr().String())
						reqID = server.logger.GetRequestID(clientIP, serverName)
						debugConn.SetRequestID(reqID)
					}

					// Check if this connection is marked for direct tunnel mode
					if debugConn.IsDirectTunnel() {
						server.logger.DebugWithRequestIDf(reqID, "[TLS-CONFIG] Connection %s is marked for direct tunnel mode, skipping TLS handshake",
							hello.Conn.RemoteAddr())

						// Return nil to indicate that we don't want to proceed with TLS
						return nil, errDirectTunnelSkip
					}

					// Get the original destination IP
					origDestIP, _ := debugConn.GetOriginalDestination()

					// Check if this IP is already marked for direct tunnel mode
					server.directTunnelMu.Lock()
					isDirectTunnel := server.directTunnelDomains[origDestIP]
					server.directTunnelMu.Unlock()

					if isDirectTunnel {
						server.logger.DebugWithRequestIDf(reqID, "[TLS-CONFIG] Original destination IP %s is marked for direct tunnel mode, skipping TLS handshake",
							origDestIP)

						// Return nil to indicate that we don't want to proceed with TLS
						return nil, errDirectTunnelSkip
					}
				}

				// If we're not in direct tunnel mode, return the default TLS config
				return &tls.Config{
					GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
						// If auto-testing is enabled, use the auto-test certificate function
						if server.autoTest {
							return server.getAutoTestCertificateFunc()(clientHello)
						}
						// Otherwise, use the standard certificate function
						return server.certManager.GetCertificateFunc(server.testType)(clientHello)
					},
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: false,            // We want clients to validate our certificates
					ClientAuth:         tls.NoClientCert, // Don't require client certificates
					CipherSuites: []uint16{
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					},
					PreferServerCipherSuites: true,
				}, nil
			},
			// We still need a GetCertificate function for backward compatibility
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// Get the server name from the client hello
				serverName := clientHello.ServerName
				if serverName == "" {
					serverName = "default.example.com"
				}

				// Get client IP
				clientIP := "unknown"
				if clientHello.Conn != nil {
					clientIP, _, _ = net.SplitHostPort(clientHello.Conn.RemoteAddr().String())
				}

				// Get a request ID for this connection
				reqID := server.logger.GetRequestID(clientIP, serverName)

				// First, check if this domain is already in the directTunnelDomains map
				server.directTunnelMu.Lock()
				isDirectTunnel := server.directTunnelDomains[serverName]
				server.directTunnelMu.Unlock()

				if isDirectTunnel {
					server.logger.InfoWithRequestIDf(reqID, "[TUNNEL-TLS] Domain %s is in directTunnelDomains map, using direct tunnel", serverName)

					// For domains in direct tunnel mode, we need to return a special error
					// that will cause the TLS handshake to fail, but in a way that allows
					// the client to reconnect using HTTP CONNECT

					// Add this domain to the direct tunnel map (redundant but ensures consistency)
					server.directTunnelMu.Lock()
					server.directTunnelDomains[serverName] = true
					server.directTunnelMu.Unlock()

					// Return a special error that will be recognized by the TLS error handler
					return nil, &DirectTunnelError{Domain: serverName}
				}

				// If auto-testing is enabled, use the auto-test certificate function
				if server.autoTest {
					cert, err := server.getAutoTestCertificateFunc()(clientHello)
					if err != nil {
						// Check if this is a DirectTunnelError
						if dtErr, ok := err.(*DirectTunnelError); ok {
							// Add this domain to the direct tunnel map
							server.directTunnelMu.Lock()
							server.directTunnelDomains[dtErr.Domain] = true
							server.directTunnelMu.Unlock()

							// Return an error to prevent the TLS handshake from continuing
							// The next connection will use the direct tunnel path above
							return nil, fmt.Errorf("%w: %s", errDirectTunnelSkip, dtErr.Domain)
						}

						// For other errors, return them as-is
						return nil, err
					}
					return cert, nil
				}

				// If auto-testing is disabled, use the standard certificate function
				return certManager.GetCertificateFunc(server.testType)(clientHello)
			},
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,            // We want clients to validate our certificates
			ClientAuth:         tls.NoClientCert, // Don't require client certificates
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			PreferServerCipherSuites: true,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	server.logger.Debugf("HTTPS server configured with TLS and certificate manager")

	return server, nil
}

// Start starts the proxy server
func (s *Server) Start() error {
	// Create debug listeners for HTTP and HTTPS
	httpListener, err := NewDebugListener(s.httpAddr, s)
	if err != nil {
		return fmt.Errorf("failed to create HTTP listener: %v", err)
	}

	httpsListener, err := NewDebugListener(s.httpsAddr, s)
	if err != nil {
		return fmt.Errorf("failed to create HTTPS listener: %v", err)
	}

	// Create a direct tunnel listener that wraps the HTTPS listener
	directTunnelListener := &DirectTunnelListener{
		Listener: httpsListener,
		server:   s,
	}

	// The HTTPS handshake listener performs the TLS handshake itself so
	// failures are recorded structurally instead of being scraped from the
	// HTTP server's error log. It is published before the HTTP proxy starts
	// because intercepted CONNECT tunnels are injected into it.
	tlsListener := newTLSHandshakeListener(directTunnelListener, s)
	s.tlsListener.Store(tlsListener)

	// Start HTTP server with debug listener
	go func() {
		s.logger.Infof("Starting HTTP proxy on %s", s.httpAddr)
		if err := s.httpServer.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			s.logger.Errorf("HTTP server error: %v", err)
		}
	}()

	s.logger.Infof("Starting HTTPS proxy on %s", s.httpsAddr)
	if err := s.httpsServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTPS server error: %v", err)
	}

	return nil
}

// Stop stops the proxy server
func (s *Server) Stop() error {
	// Persist pending test results and stop the background flush loop
	defer s.tester.Close()

	// Stop HTTP server
	if err := s.httpServer.Close(); err != nil {
		s.logger.Errorf("Error stopping HTTP server: %v", err)
	}

	// Stop HTTPS server
	if err := s.httpsServer.Close(); err != nil {
		s.logger.Errorf("Error stopping HTTPS server: %v", err)
		return err
	}

	return nil
}

// SetTestType sets the test type
func (s *Server) SetTestType(testType certificates.TestType) {
	s.testType = testType

	// Update the tester's test order to start with this test type
	s.tester.UpdateTestOrder(testType)

	// If auto-testing is disabled, update the certificate function
	if !s.autoTest {
		s.httpsServer.TLSConfig.GetCertificate = s.certManager.GetCertificateFunc(testType)
	}

	// Reset the failed handshakes map
	s.handshakesMu.Lock()
	s.failedHandshakes = make(map[string]map[certificates.TestType]bool)
	s.handshakesMu.Unlock()

	// Log the test type change
	s.logger.Infof("Test type set to: %s", testType.GetTestTypeName())
}

// SetAutoTest enables or disables automatic testing
func (s *Server) SetAutoTest(enabled bool) {
	s.autoTest = enabled

	// We don't need to update the certificate function anymore
	// because we're now handling it in the TLSConfig.GetCertificate function
	// which checks s.autoTest internally

	if enabled {
		s.logger.Infof("Automatic testing enabled - will try all test types for each domain")
	} else {
		s.logger.Infof("Automatic testing disabled - using fixed test type: %s", s.testType.GetTestTypeName())
	}
}

// SetMaxAttempts sets the maximum number of attempts for each test type
func (s *Server) SetMaxAttempts(maxAttempts int) {
	s.tester.maxAttempts = maxAttempts
	s.logger.Infof("Maximum attempts per test type set to: %d", maxAttempts)
}

// RecordFailedHandshake records a failed handshake for a domain and test type
func (s *Server) RecordFailedHandshake(domain string, testType certificates.TestType, reqID string) certificates.TestType {
	// Get the domain test status before recording the failure
	domainStatus := s.tester.GetTestStatus(domain)
	if domainStatus != nil {
		s.logger.DebugWithRequestIDf(reqID, "[DOMAIN] Before recording failure - Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
			domain, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)
	}

	// Record the failure in the failedHandshakes map
	s.handshakesMu.Lock()
	if _, exists := s.failedHandshakes[domain]; !exists {
		s.failedHandshakes[domain] = make(map[certificates.TestType]bool)
	}
	s.failedHandshakes[domain][testType] = true
	s.handshakesMu.Unlock()

	// Record the failure in the tester and get the next test to try
	nextTest := s.tester.RecordTestResult(domain, testType, false)
	s.logger.InfoWithRequestIDf(reqID, "[FAILURE] Recorded failed handshake for %s with %s, next test: %s",
		domain, testType.GetTestTypeName(), nextTest.GetTestTypeName())

	// Get the domain test status after recording the failure
	domainStatus = s.tester.GetTestStatus(domain)
	if domainStatus != nil {
		s.logger.DebugWithRequestIDf(reqID, "[DOMAIN] After recording failure - Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
			domain, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)
	}

	// Make sure the next test is marked as not failed yet
	if nextTest != certificates.DirectTunnel {
		s.handshakesMu.Lock()
		// Reset all test types to ensure we don't have stale failure data
		for testType := range s.failedHandshakes[domain] {
			s.failedHandshakes[domain][testType] = false
		}
		// Mark the current test as failed
		s.failedHandshakes[domain][testType] = true
		s.handshakesMu.Unlock()
		s.logger.DebugWithRequestIDf(reqID, "[TEST] Reset failure status for all tests for domain %s", domain)
	}

	return nextTest
}

// getAutoTestCertificateFunc returns a certificate function that automatically tests all methods
func (s *Server) getAutoTestCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Get the server name from the client hello
		serverName := clientHello.ServerName
		if serverName == "" {
			serverName = "default.example.com"
		}

		// Get the client IP
		clientIP := "unknown"
		if clientHello.Conn != nil {
			clientIP, _, _ = net.SplitHostPort(clientHello.Conn.RemoteAddr().String())

			// If this is a DebugConnection, set the domain and client IP
			if debugConn, ok := clientHello.Conn.(*DebugConnection); ok {
				// Get or create a request ID
				reqID := debugConn.reqID
				if reqID == "" {
					reqID = s.logger.GetRequestID(clientIP, serverName)
				}

				// Check if this connection is already marked for direct tunnel mode
				if debugConn.IsDirectTunnel() {
					// This connection is already marked for direct tunnel mode
					// We should return a special error to prevent TLS handshake
					s.logger.DebugWithRequestIDf(reqID, "[TLS-HELLO] Connection %s is marked for direct tunnel mode, skipping TLS handshake",
						clientHello.Conn.RemoteAddr())

					// Get the original destination IP
					origDestIP, _ := debugConn.GetOriginalDestination()

					// Make sure this domain and IP are in the direct tunnel map
					s.directTunnelMu.Lock()
					s.directTunnelDomains[serverName] = true
					if origDestIP != "" {
						s.directTunnelDomains[origDestIP] = true
					}
					s.directTunnelMu.Unlock()

					// Return a special error that will be recognized by the TLS error handler
					return nil, &DirectTunnelError{Domain: serverName}
				}

				debugConn.SetDomain(serverName)
				debugConn.SetClientIP(clientIP)

				// Set the request ID as well
				reqID = s.logger.GetRequestID(clientIP, serverName)
				debugConn.SetRequestID(reqID)

				s.logger.DebugWithRequestIDf(reqID, "[TLS-HELLO] Set domain %s and client IP %s on connection %s",
					serverName, clientIP, clientHello.Conn.RemoteAddr())
			}
		}

		// Add to recent domains list
		s.AddRecentDomain(serverName)

		// Get a request ID for this connection
		reqID := s.logger.GetRequestID(clientIP, serverName)

		// Resolve the server name to an IP address
		var destIP string
		if net.ParseIP(serverName) != nil {
			destIP = serverName
		} else {
			// Resolve the domain to an IP address
			ips, resolveErr := net.LookupIP(serverName)
			if resolveErr == nil && len(ips) > 0 {
				// Use the first IP address
				destIP = ips[0].String()
				s.logger.DebugWithRequestIDf(reqID, "[TEST] Resolved server name %s to IP %s", serverName, destIP)
			}
		}

		// First, check if this domain or IP is already in the directTunnelDomains map
		s.directTunnelMu.Lock()
		isDirectTunnel := s.directTunnelDomains[serverName]
		if !isDirectTunnel && destIP != "" {
			isDirectTunnel = s.directTunnelDomains[destIP]
		}
		s.directTunnelMu.Unlock()

		if isDirectTunnel {
			s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Domain %s or IP %s is already in directTunnelDomains map, using direct tunnel",
				serverName, destIP)
			return nil, &DirectTunnelError{Domain: serverName}
		}

		// Get the next test to try. With SNI, results are keyed by the
		// hostname - the same key the handshake listener records failures
		// under - so selection, failures and successes share one status.
		// Only SNI-less connections fall back to IP-based grouping.
		var testType certificates.TestType
		if clientHello.ServerName != "" && !isIPAddress(clientHello.ServerName) {
			testType = s.tester.GetNextTest(serverName)
			s.logger.DebugWithRequestIDf(reqID, "[TEST] Initial test type for domain %s: %s", serverName, testType.GetTestTypeName())
		} else if destIP != "" {
			// Try to get the test by IP first
			testType = s.tester.GetNextTestByIP(destIP)
			s.logger.DebugWithRequestIDf(reqID, "[TEST] Initial test type for IP %s: %s", destIP, testType.GetTestTypeName())
		} else {
			// Fall back to domain-based lookup
			testType = s.tester.GetNextTest(serverName)
			s.logger.DebugWithRequestIDf(reqID, "[TEST] Initial test type for domain %s: %s", serverName, testType.GetTestTypeName())
		}

		// If we should use a direct tunnel, we need to handle this specially
		// We'll return a special error that our TLS config will recognize
		if testType == certificates.DirectTunnel {
			s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Using direct tunnel for %s - all tests failed", serverName)
			// Store this domain in a special map to indicate it should use direct tunnel
			s.directTunnelMu.Lock()
			s.directTunnelDomains[serverName] = true
			if destIP != "" {
				s.directTunnelDomains[destIP] = true
			}
			s.directTunnelMu.Unlock()
			return nil, &DirectTunnelError{Domain: serverName}
		}

		// Check if this test has already failed for this connection
		s.handshakesMu.Lock()
		if _, exists := s.failedHandshakes[serverName]; !exists {
			s.failedHandshakes[serverName] = make(map[certificates.TestType]bool)
		}

		// Check the domain test status to ensure we're using the correct test
		domainStatus := s.tester.GetTestStatus(serverName)
		if domainStatus != nil {
			s.logger.DebugWithRequestIDf(reqID, "[DOMAIN] %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
				serverName, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)

			// Make sure we're using the correct test type based on the domain status
			if !domainStatus.TestsCompleted && !domainStatus.SuccessfulTestSet &&
				domainStatus.CurrentTestIndex < len(s.tester.GetTestOrder()) {
				correctTestType := s.tester.GetTestOrder()[domainStatus.CurrentTestIndex]
				if testType != correctTestType {
					s.logger.DebugWithRequestIDf(reqID, "[TEST] Correcting test type from %s to %s based on domain status",
						testType.GetTestTypeName(), correctTestType.GetTestTypeName())
					testType = correctTestType
				}
			}
		}

		if s.failedHandshakes[serverName][testType] {
			// This test has already failed, move to the next one
			nextTest := s.tester.RecordTestResult(serverName, testType, false)
			s.handshakesMu.Unlock()

			if nextTest == certificates.DirectTunnel {
				s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Using direct tunnel for %s - all tests failed", serverName)
				// Store this domain in the direct tunnel map
				s.directTunnelMu.Lock()
				s.directTunnelDomains[serverName] = true
				s.directTunnelMu.Unlock()
				return nil, &DirectTunnelError{Domain: serverName}
			}

			// Try the next test
			s.logger.InfoWithRequestIDf(reqID, "[TEST] Test %s failed for %s, trying %s", testType.GetTestTypeName(), serverName, nextTest.GetTestTypeName())
			testType = nextTest
		} else {
			s.handshakesMu.Unlock()
		}

		// Log the test being performed
		s.logger.InfoWithRequestIDf(reqID, "[TEST] Testing %s from %s with %s", serverName, clientIP, testType.GetTestTypeName())

		// Get the certificate for this test
		cert, err := s.certManager.GetCertificate(serverName, testType)
		if err != nil {
			s.logger.ErrorWithRequestIDf(reqID, "[ERROR] Failed to get certificate for %s: %v", serverName, err)

			// Record the failure and try the next test
			s.handshakesMu.Lock()
			s.failedHandshakes[serverName][testType] = true
			s.handshakesMu.Unlock()

			nextTest := s.tester.RecordTestResult(serverName, testType, false)
			if nextTest == certificates.DirectTunnel {
				s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Using direct tunnel for %s - all tests failed", serverName)
				// Store this domain in the direct tunnel map
				s.directTunnelMu.Lock()
				s.directTunnelDomains[serverName] = true
				s.directTunnelMu.Unlock()
				return nil, &DirectTunnelError{Domain: serverName}
			}

			// Try the next test by calling this function again with the same clientHello
			s.logger.InfoWithRequestIDf(reqID, "[TEST] Test %s failed for %s, trying %s", testType.GetTestTypeName(), serverName, nextTest.GetTestTypeName())
			return s.getAutoTestCertificateFunc()(clientHello)
		}

		// Mark this test as attempted but not yet failed
		// We'll only know if it failed when we get a TLS handshake error
		s.handshakesMu.Lock()
		s.failedHandshakes[serverName][testType] = false
		s.handshakesMu.Unlock()

		s.logger.DebugWithRequestIDf(reqID, "[CERT] Successfully got certificate for %s with test type %s",
			serverName, testType.GetTestTypeName())

		return cert, nil
	}
}

// SetSavePayloads enables or disables saving of request and response payloads
func (s *Server) SetSavePayloads(save bool) {
	s.savePayloads = save
}

// SetPayloadDir sets the directory for saving payloads
func (s *Server) SetPayloadDir(dir string) error {
	payloadLogger, err := logging.NewPayloadLogger(dir)
	if err != nil {
		return fmt.Errorf("failed to create payload logger: %v", err)
	}
	s.payloadLogger = payloadLogger
	s.payloadDir = dir
	return nil
}

// AddRecentDomain adds a domain to the list of recently accessed domains
func (s *Server) AddRecentDomain(domain string) {
	s.recentDomainsMu.Lock()
	defer s.recentDomainsMu.Unlock()

	// Skip empty domains or IP addresses
	if domain == "" || isIPAddress(domain) {
		return
	}

	// Check if the domain is already in the list
	found := false
	for i, d := range s.recentDomains {
		if d == domain {
			// If found, move it to the end of the list (most recent)
			if i < len(s.recentDomains)-1 {
				// Remove from current position
				s.recentDomains = append(s.recentDomains[:i], s.recentDomains[i+1:]...)
				// Add to the end
				s.recentDomains = append(s.recentDomains, domain)
				s.logger.Debugf("Moved domain to end of recent list: %s", domain)
			}
			found = true
			break
		}
	}

	// If not found, add the domain to the list
	if !found {
		s.recentDomains = append(s.recentDomains, domain)
		s.logger.Debugf("Added domain to recent list: %s", domain)
	}

	// If the list is too long, remove the oldest domain
	if len(s.recentDomains) > 10 {
		s.recentDomains = s.recentDomains[1:]
	}
}

// GetRecentDomains returns the list of recently accessed domains
func (s *Server) GetRecentDomains() []string {
	s.recentDomainsMu.Lock()
	defer s.recentDomainsMu.Unlock()

	// Return a copy of the list
	domains := make([]string, len(s.recentDomains))
	copy(domains, s.recentDomains)

	return domains
}

// handleHTTP handles HTTP requests
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Get client IP
	clientIP := getClientIP(r)

	// Get a request ID for this connection
	reqID := s.logger.GetRequestID(clientIP, r.Host)

	// Print immediate debug information about the connection
	s.logger.DebugWithRequestIDf(reqID, "[HTTP-CONNECTION] New HTTP connection from %s to %s (Method: %s, URL: %s, Proto: %s)",
		clientIP, r.Host, r.Method, r.URL, r.Proto)

	// Log all request headers for debugging
	s.logger.DebugWithRequestIDf(reqID, "[HTTP-HEADERS] Request headers from %s:", clientIP)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.DebugWithRequestIDf(reqID, "[HTTP-HEADERS]   %s: %s", name, value)
		}
	}

	// Extract the host and port
	host := r.Host
	var hostWithoutPort string

	if strings.Contains(host, ":") {
		var splitErr error
		hostWithoutPort, _, splitErr = net.SplitHostPort(host)
		if splitErr != nil {
			s.logger.Errorf("Failed to split host and port: %v", splitErr)
			hostWithoutPort = host
		}
	} else {
		hostWithoutPort = host
	}

	// Add to recent domains list if it's a domain (not an IP)
	s.AddRecentDomain(hostWithoutPort)

	// Resolve the destination IP from the host
	var destIP string

	// Check if the host is already an IP address
	if net.ParseIP(hostWithoutPort) != nil {
		destIP = hostWithoutPort
	} else {
		// Resolve the domain to an IP address
		ips, err := net.LookupIP(hostWithoutPort)
		if err != nil {
			// Continue with the domain name even if we can't resolve it
		} else if len(ips) > 0 {
			// Use the first IP address
			destIP = ips[0].String()
			s.logger.Debugf("Resolved host %s to IP %s", hostWithoutPort, destIP)
		}
	}

	// Log request
	s.logger.LogRequest(clientIP, r.Method, r.Host, r.URL.Path, false)

	// Track connection
	s.trackConnection(clientIP, true)
	defer s.trackConnection(clientIP, false)

	// Check if this is a CONNECT request (for HTTPS)
	if r.Method == http.MethodConnect {
		s.logger.Debugf("Handling CONNECT request for %s from %s", r.Host, clientIP)
		s.handleConnect(w, r)
		return
	}

	// Handle regular HTTP request
	s.handleRegularHTTP(w, r, "http", nil)
}

// handleHTTPS handles HTTPS requests
func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Get client IP
	clientIP := getClientIP(r)

	// Get a request ID for this connection
	reqID := s.logger.GetRequestID(clientIP, r.Host)

	// Print immediate debug information about the connection
	s.logger.DebugWithRequestIDf(reqID, "[HTTPS-CONNECTION] New HTTPS connection from %s to %s (Method: %s, URL: %s, Proto: %s)",
		clientIP, r.Host, r.Method, r.URL, r.Proto)

	// Log all request headers for debugging
	s.logger.DebugWithRequestIDf(reqID, "[HTTPS-HEADERS] Request headers from %s:", clientIP)
	for name, values := range r.Header {
		for _, value := range values {
			s.logger.DebugWithRequestIDf(reqID, "[HTTPS-HEADERS]   %s: %s", name, value)
		}
	}

	// Extract the host and port
	host := r.Host
	var hostWithoutPort string

	if strings.Contains(host, ":") {
		var splitErr error
		hostWithoutPort, _, splitErr = net.SplitHostPort(host)
		if splitErr != nil {
			s.logger.Errorf("Failed to split host and port: %v", splitErr)
			hostWithoutPort = host
		}
	} else {
		hostWithoutPort = host
	}

	// Add to recent domains list if it's a domain (not an IP)
	s.AddRecentDomain(hostWithoutPort)

	// Resolve the destination IP from the host
	var destIP string

	// Check if the host is already an IP address
	if net.ParseIP(hostWithoutPort) != nil {
		destIP = hostWithoutPort
	} else {
		// Resolve the domain to an IP address
		ips, err := net.LookupIP(hostWithoutPort)
		if err != nil {
			s.logger.Errorf("Failed to resolve host %s: %v", hostWithoutPort, err)
			// Continue with the domain name even if we can't resolve it
		} else if len(ips) > 0 {
			// Use the first IP address
			destIP = ips[0].String()
			s.logger.Debugf("Resolved host %s to IP %s", hostWithoutPort, destIP)
		}
	}

	// Log request
	s.logger.LogRequest(clientIP, r.Method, r.Host, r.URL.Path, true)

	// Track connection
	s.trackConnection(clientIP, true)
	defer s.trackConnection(clientIP, false)

	// The certificate test the client accepted to get here
	appliedTest := s.testType

	// If auto-testing is enabled, record a successful test
	if s.autoTest {
		// Record successful test for this domain or IP
		// We know the test was successful because we're handling an HTTPS request
		var currentTest certificates.TestType
		var nextTest certificates.TestType

		// Get a request ID for this connection
		reqID := s.logger.GetRequestID(clientIP, hostWithoutPort)

		if sni := tlsServerName(r); sni != "" {
			// Record under the SNI hostname, matching certificate selection
			// and handshake-failure recording
			currentTest = s.tester.GetNextTest(sni)
			nextTest = s.tester.RecordTestResult(sni, currentTest, true)
			s.logger.InfoWithRequestIDf(reqID, "[SUCCESS] Successful MITM for domain %s (url: %s) using %s",
				sni, r.URL.String(), currentTest.GetTestTypeName())
		} else if destIP != "" {
			// Use IP-based lookup first
			currentTest = s.tester.GetNextTestByIP(destIP)
			nextTest = s.tester.RecordTestResult(destIP, currentTest, true)
			s.logger.InfoWithRequestIDf(reqID, "[SUCCESS] Successful MITM for IP %s (host: %s, url: %s) using %s",
				destIP, hostWithoutPort, r.URL.String(), currentTest.GetTestTypeName())
		} else {
			// Fall back to domain-based lookup
			currentTest = s.tester.GetNextTest(hostWithoutPort)
			nextTest = s.tester.RecordTestResult(hostWithoutPort, currentTest, true)
			s.logger.InfoWithRequestIDf(reqID, "[SUCCESS] Successful MITM for domain %s (url: %s) using %s",
				hostWithoutPort, r.URL.String(), currentTest.GetTestTypeName())
		}

		appliedTest = currentTest

		// If the next test is different, update the certificate function
		if nextTest != currentTest {
			s.logger.InfoWithRequestIDf(reqID, "[NEXT] Moving to next test for %s: %s", host, nextTest.GetTestTypeName())
		}
	}

	// Handle regular HTTP request (but over HTTPS)
	s.handleRegularHTTP(w, r, "https", &appliedTest)
}

// handleConnect handles CONNECT requests (for HTTPS)
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Get client IP
	clientIP := getClientIP(r)

	// Log immediate debug information about the CONNECT request
	s.logger.Debugf("[CONNECT-REQUEST] New CONNECT request from %s to %s (Proto: %s)",
		clientIP, r.Host, r.Proto)

	// NOTE: Connection-level direct-tunnel checks are not done here. The
	// connection must not be hijacked at this point; it is hijacked exactly
	// once below for whichever mode is selected (direct tunnel or MITM).

	// Extract the host and port
	host := r.Host
	var hostWithoutPort string

	if strings.Contains(host, ":") {
		var splitErr error
		hostWithoutPort, _, splitErr = net.SplitHostPort(host)
		if splitErr != nil {
			s.logger.Errorf("Failed to split host and port: %v", splitErr)
			hostWithoutPort = host
		}
	} else {
		hostWithoutPort = host
	}

	// Add to recent domains list if it's a domain (not an IP)
	s.AddRecentDomain(hostWithoutPort)

	// Resolve the destination IP from the host
	var destIP string

	// Check if the host is already an IP address
	if net.ParseIP(hostWithoutPort) != nil {
		destIP = hostWithoutPort
	} else {
		// Resolve the domain to an IP address
		ips, err := net.LookupIP(hostWithoutPort)
		if err != nil {
			s.logger.Errorf("Failed to resolve host %s: %v", hostWithoutPort, err)
			// Continue with the domain name even if we can't resolve it
		} else if len(ips) > 0 {
			// Use the first IP address
			destIP = ips[0].String()
			s.logger.Debugf("Resolved host %s to IP %s", hostWithoutPort, destIP)
		}
	}

	// Get a request ID for this connection
	reqID := s.logger.GetRequestID(clientIP, hostWithoutPort)

	// Store the destination information for this client IP
	// This will help us identify the destination for non-TLS connections
	s.clientDestMu.Lock()
	s.clientDestinations[clientIP] = r.Host
	s.logger.DebugWithRequestIDf(reqID, "[DEST] Stored destination %s for client %s", r.Host, clientIP)
	s.clientDestMu.Unlock()

	// Check if we should use a direct tunnel based on IP or domain
	useTunnel := false
	isMQTT := false

	// Check if this is an MQTT connection based on the URL format or hostname
	// MQTT over SSL URLs often start with "ssl://" or "mqtts://"
	// Also check for common MQTT hostnames
	if strings.HasPrefix(strings.ToLower(hostWithoutPort), "ssl://") ||
		strings.HasPrefix(strings.ToLower(hostWithoutPort), "mqtts://") ||
		strings.Contains(strings.ToLower(hostWithoutPort), "mqtt") {
		// Mark as MQTT but don't automatically use direct tunnel
		// We'll try to MITM it first, and fall back to direct tunnel if that fails
		isMQTT = true
		s.logger.InfoWithRequestIDf(reqID, "[MQTT] Detected MQTT connection to %s - will attempt MITM", hostWithoutPort)

		// Add a special log entry to make it very clear we're dealing with an MQTT connection
		s.logger.InfoWithRequestIDf(reqID, "[MQTT-ALERT] *** MQTT CONNECTION DETECTED: %s - MQTT connections are persistent and may not show obvious failures ***", hostWithoutPort)
	}

	// First, check if this domain or IP is in the directTunnelDomains map
	if !useTunnel {
		s.directTunnelMu.Lock()
		if s.directTunnelDomains[hostWithoutPort] || (destIP != "" && s.directTunnelDomains[destIP]) {
			useTunnel = true
			s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Domain %s or IP %s is in directTunnelDomains map", hostWithoutPort, destIP)

			// Log that we're using direct tunnel mode with no inspection or modification
			s.logger.InfoWithRequestIDf(reqID, "[TUNNEL-DIRECT] Using direct tunnel for %s - pure passthrough mode with no inspection or modification", hostWithoutPort)
		}
		s.directTunnelMu.Unlock()
	}

	// Check if the domain has completed all tests with no success
	if !useTunnel {
		// Get the domain test status
		domainStatus := s.tester.GetTestStatus(hostWithoutPort)
		if domainStatus != nil {
			s.logger.DebugWithRequestIDf(reqID, "[CONNECT] Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
				hostWithoutPort, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)

			// If we've already completed all tests with no success, we should be in direct tunnel mode
			if domainStatus.TestsCompleted && !domainStatus.SuccessfulTestSet {
				useTunnel = true
				s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Domain %s has completed all tests with no success, using DirectTunnel", hostWithoutPort)

				// Make sure this domain is in the direct tunnel map
				s.directTunnelMu.Lock()
				s.directTunnelDomains[hostWithoutPort] = true
				s.directTunnelMu.Unlock()
			}
		}

		// Also check by IP if we have a destination IP
		if !useTunnel && destIP != "" {
			// Get the domain test status by IP
			ipStatus := s.tester.GetTestStatusByIP(destIP)
			if ipStatus != nil {
				s.logger.DebugWithRequestIDf(reqID, "[CONNECT] IP %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
					destIP, ipStatus.CurrentTestIndex, ipStatus.TestsCompleted, ipStatus.SuccessfulTestSet)

				// If we've already completed all tests with no success, we should be in direct tunnel mode
				if ipStatus.TestsCompleted && !ipStatus.SuccessfulTestSet {
					useTunnel = true
					s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] IP %s has completed all tests with no success, using DirectTunnel", destIP)

					// Make sure this IP is in the direct tunnel map
					s.directTunnelMu.Lock()
					s.directTunnelDomains[destIP] = true
					s.directTunnelMu.Unlock()
				}
			}
		}
	}

	// If not already marked for direct tunnel, check the tester
	if !useTunnel && s.autoTest {
		// Check the domain status first to see if all tests have been completed
		domainStatus := s.tester.GetTestStatus(hostWithoutPort)
		if domainStatus != nil {
			s.logger.InfoWithRequestIDf(reqID, "[DOMAIN] Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
				hostWithoutPort, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)

			// Double-check that if TestsCompleted is true, we're properly handling it
			if domainStatus.TestsCompleted {
				s.logger.InfoWithRequestIDf(reqID, "[DOMAIN-CHECK] Domain %s has TestsCompleted=true, checking if we should use direct tunnel", hostWithoutPort)
			}

			// If all tests are completed and none succeeded, use direct tunnel
			if domainStatus.TestsCompleted && !domainStatus.SuccessfulTestSet {
				useTunnel = true
				s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Domain %s has completed all tests with no success, using direct tunnel", hostWithoutPort)

				// Add to the directTunnelDomains map
				s.directTunnelMu.Lock()
				s.directTunnelDomains[hostWithoutPort] = true
				if destIP != "" {
					s.directTunnelDomains[destIP] = true
				}
				s.directTunnelMu.Unlock()
			}
		}

		// If we're not already using a tunnel, check by IP and domain
		if !useTunnel {
			if destIP != "" {
				// Use IP-based lookup first
				useTunnel = s.tester.ShouldUseTunnelByIP(destIP)
				s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Checking tunnel status for IP %s: %v", destIP, useTunnel)
			}

			// If we couldn't determine by IP or it's not a tunnel, check by domain
			if destIP == "" || !useTunnel {
				domainTunnel := s.tester.ShouldUseTunnel(hostWithoutPort)
				if domainTunnel {
					useTunnel = true
				}
				s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Checking tunnel status for domain %s: %v", hostWithoutPort, domainTunnel)
			}

			// If we should use a tunnel, add to the directTunnelDomains map for future connections
			if useTunnel {
				s.directTunnelMu.Lock()
				s.directTunnelDomains[hostWithoutPort] = true
				if destIP != "" {
					s.directTunnelDomains[destIP] = true
				}
				s.directTunnelMu.Unlock()
			}
		}

		// Log the final decision
		if useTunnel {
			if isMQTT {
				s.logger.InfoWithRequestIDf(reqID, "[MQTT] Will use direct tunnel for MQTT connection to %s (IP: %s)", hostWithoutPort, destIP)
			} else {
				s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Will use direct tunnel for %s (IP: %s)", hostWithoutPort, destIP)
			}
		} else {
			s.logger.InfoWithRequestIDf(reqID, "[TUNNEL] Will attempt MITM for %s (IP: %s)", hostWithoutPort, destIP)
		}
	}

	if useTunnel {
		if isMQTT {
			s.logger.InfoWithRequestIDf(reqID, "CONNECT request for %s from %s - using direct tunnel for MQTT connection", r.Host, clientIP)
		} else {
			s.logger.InfoWithRequestIDf(reqID, "CONNECT request for %s from %s - using direct tunnel (all tests failed)", r.Host, clientIP)
		}
		s.handleDirectTunnel(w, r)
		return
	}

	if isMQTT {
		s.logger.InfoWithRequestIDf(reqID, "[MQTT] CONNECT request for %s from %s", r.Host, clientIP)
	} else {
		s.logger.InfoWithRequestIDf(reqID, "[CONNECT] Request for %s from %s", r.Host, clientIP)
	}

	// The certificate under test is chosen during the TLS handshake (from the
	// SNI), exactly as for transparently redirected connections
	s.interceptConnect(w, r, reqID, clientIP)
}

// newRegularTransport builds the shared transport used to relay decrypted
// requests to their target servers. Connections are pooled across requests so
// that a Transport is not created per request.
func newRegularTransport() *http.Transport {
	return &http.Transport{
		// Accept any certificate presented by the server
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableCompression: true,
		// Add more aggressive timeouts
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
}

// handleRegularHTTP handles a client request that is already decrypted.
// The scheme selects how the target request is re-issued: "https" when the
// original connection was TLS (decrypted MITM traffic) and "http" for plain
// HTTP proxying on the plain port. mitmTest is the certificate test the client
// accepted for decrypted traffic and nil for plain HTTP.
func (s *Server) handleRegularHTTP(w http.ResponseWriter, r *http.Request, scheme string, mitmTest *certificates.TestType) {
	// Get client IP and host
	clientIP := getClientIP(r)
	host := r.Host

	// One request ID shared by the request/response payloads and the event
	reqID := s.logger.GetRequestID(clientIP, host)
	started := time.Now()
	evt := RequestEvent{
		ReqID:    reqID,
		ClientIP: clientIP,
		Method:   r.Method,
		Scheme:   scheme,
		Host:     host,
		Path:     r.URL.Path,
		Query:    r.URL.RawQuery,
		Saved:    s.savePayloads,
	}
	if mitmTest != nil {
		evt.TestType = TestTypeKey(*mitmTest)
	}
	defer func() {
		evt.DurationMs = float64(time.Since(started).Microseconds()) / 1000
		s.publishRequest(evt)
	}()

	s.logger.Debugf("Handling request from %s to %s", clientIP, host)

	// Create a copy of the request body for logging
	var requestBodyCopy []byte
	if r.Body != nil {
		requestBodyCopy, _ = io.ReadAll(r.Body)
		// Restore the body for further processing
		r.Body = io.NopCloser(bytes.NewReader(requestBodyCopy))
	}

	// Log request payload if enabled
	if s.savePayloads {
		// Create a copy of the request for logging
		reqCopy := *r
		if requestBodyCopy != nil {
			reqCopy.Body = io.NopCloser(bytes.NewReader(requestBodyCopy))
		}

		if err := s.payloadLogger.LogRequest(clientIP, host, &reqCopy, reqID); err != nil {
			s.logger.Errorf("Failed to log request payload: %v", err)
		}
	}

	// Construct a proper URL with scheme
	targetURL := fmt.Sprintf("%s://%s%s", scheme, host, r.URL.Path)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	s.logger.Debugf("Constructed target URL: %s", targetURL)

	// Create a new request to the target server
	var targetReq *http.Request
	var err error
	if requestBodyCopy != nil {
		targetReq, err = http.NewRequest(r.Method, targetURL, bytes.NewReader(requestBodyCopy))
	} else {
		targetReq, err = http.NewRequest(r.Method, targetURL, nil)
	}

	if err != nil {
		s.logger.Errorf("Failed to create target request: %v", err)
		evt.Error = err.Error()
		evt.Status = http.StatusInternalServerError
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			targetReq.Header.Add(key, value)
		}
	}

	// HTTP client with shared transport that accepts any certificate
	client := &http.Client{
		Transport: s.regularTransport,
		Timeout:   30 * time.Second,
		// Don't follow redirects automatically
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	s.logger.Debugf("Created HTTP client with InsecureSkipVerify=true for %s", host)

	s.logger.Debugf("Sending request to target server: %s %s", r.Method, r.URL.String())

	// Send request to target server
	targetResp, err := client.Do(targetReq)
	if err != nil {
		s.logger.Errorf("Failed to send request to target server: %v", err)
		evt.Error = err.Error()
		evt.Status = http.StatusInternalServerError
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer targetResp.Body.Close()

	s.logger.Debugf("Received response from target server: %d %s", targetResp.StatusCode, targetResp.Status)

	// Read the response body
	responseBody, err := io.ReadAll(targetResp.Body)
	if err != nil {
		s.logger.Errorf("Failed to read response body: %v", err)
		evt.Error = err.Error()
		evt.Status = http.StatusInternalServerError
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Restore the response body for further processing
	targetResp.Body = io.NopCloser(bytes.NewReader(responseBody))

	// Log response payload if enabled
	if s.savePayloads {
		// Create a copy of the response for logging
		respCopy := *targetResp
		respCopy.Body = io.NopCloser(bytes.NewReader(responseBody))

		if err := s.payloadLogger.LogResponse(clientIP, host, &respCopy, reqID); err != nil {
			s.logger.Errorf("Failed to log response payload: %v", err)
		}
	}

	// Copy response headers
	for key, values := range targetResp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set response status code
	w.WriteHeader(targetResp.StatusCode)
	evt.Status = targetResp.StatusCode
	evt.ReqBytes = len(requestBodyCopy)
	evt.RespBytes = len(responseBody)
	evt.ContentType = targetResp.Header.Get("Content-Type")

	// Write response body
	if _, err := w.Write(responseBody); err != nil {
		s.logger.Errorf("Failed to write response body: %v", err)
	}

	// With a fixed test type every decrypted request is a successful MITM;
	// in auto-test mode handleHTTPS already logged the success
	if mitmTest != nil && !s.autoTest {
		s.logger.InfoWithRequestIDf(reqID, "[SUCCESS] Successfully intercepted request from %s to %s (url: %s) (Test: %s)",
			clientIP, host, r.URL.String(), mitmTest.GetTestTypeName())
	}
}

// trackConnection tracks client connections
func (s *Server) trackConnection(clientIP string, isConnect bool) {
	s.connectionMu.Lock()
	defer s.connectionMu.Unlock()

	if isConnect {
		s.connections[clientIP]++
	} else {
		s.connections[clientIP]--
		if s.connections[clientIP] <= 0 {
			delete(s.connections, clientIP)

			// Also clean up the client destination mapping when the last connection is closed
			s.clientDestMu.Lock()
			if _, exists := s.clientDestinations[clientIP]; exists {
				s.logger.Debugf("[DEST] Removing destination mapping for client %s", clientIP)
				delete(s.clientDestinations, clientIP)
			}
			s.clientDestMu.Unlock()
		}
	}
}

// getClientIP gets the client IP address
func getClientIP(r *http.Request) string {
	// Use the actual connection address. Headers such as X-Forwarded-For and
	// X-Real-IP are fully client controlled, so trusting them would let any
	// client spoof the IP that test results are keyed on.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// tlsServerName returns the SNI hostname of a decrypted request, or "" when
// the client sent none (or sent an IP literal)
func tlsServerName(r *http.Request) string {
	if r.TLS == nil || r.TLS.ServerName == "" || isIPAddress(r.TLS.ServerName) {
		return ""
	}
	return r.TLS.ServerName
}

// isIPAddress checks if a string is an IP address
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// HandleConnectionReset records a connection reset as a test failure
// This is called when a client resets the connection during a TLS handshake
func (s *Server) HandleConnectionReset(clientIP, domain string) {
	// Get a request ID for this connection
	reqID := s.logger.GetRequestID(clientIP, domain)

	// Get the domain test status before checking anything else
	domainStatus := s.tester.GetTestStatus(domain)
	if domainStatus != nil {
		s.logger.DebugWithRequestIDf(reqID, "[CONN-RESET] Domain %s status before handling reset: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
			domain, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)

		// If we've already completed all tests with no success, we should be in direct tunnel mode
		if domainStatus.TestsCompleted && !domainStatus.SuccessfulTestSet {
			// Make sure this domain is in the direct tunnel map
			s.directTunnelMu.Lock()
			s.directTunnelDomains[domain] = true
			s.directTunnelMu.Unlock()

			s.logger.InfoWithRequestIDf(reqID, "[CONN-RESET] Domain %s has already completed all tests with no success, ignoring connection reset and using DirectTunnel", domain)
			return
		}
	}

	// Check if this domain is in the direct tunnel map
	s.directTunnelMu.Lock()
	isDirectTunnel := s.directTunnelDomains[domain]
	s.directTunnelMu.Unlock()

	if isDirectTunnel {
		// This is a direct tunnel connection, so we should ignore connection resets
		s.logger.DebugWithRequestIDf(reqID, "[CONN-RESET] Ignoring connection reset for domain %s as it's in direct tunnel mode", domain)
		return
	}

	// Get the current test type for this domain
	testType := s.tester.GetNextTest(domain)

	// Check if the current test type is DirectTunnel
	if testType == certificates.DirectTunnel {
		// We're already in direct tunnel mode, so we should ignore this error
		s.logger.DebugWithRequestIDf(reqID, "[CONN-RESET] Ignoring connection reset for domain %s as test type is DirectTunnel", domain)

		// Make sure this domain is in the direct tunnel map
		s.directTunnelMu.Lock()
		s.directTunnelDomains[domain] = true
		s.directTunnelMu.Unlock()

		return
	}

	// Get the domain test status before recording the failure (refresh it)
	domainStatus = s.tester.GetTestStatus(domain)
	if domainStatus != nil {
		s.logger.DebugWithRequestIDf(reqID, "[DOMAIN] Before connection reset - Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
			domain, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)
	}

	// Record the connection reset as a handshake failure
	s.logger.InfoWithRequestIDf(reqID, "[CONN-RESET] Connection reset from %s for %s with test type %s - treating as handshake failure",
		clientIP, domain, testType.GetTestTypeName())

	// Record the failure and get the next test type
	nextTest := s.RecordFailedHandshake(domain, testType, reqID)

	// Get the domain test status after recording the failure
	domainStatus = s.tester.GetTestStatus(domain)
	if domainStatus != nil {
		s.logger.DebugWithRequestIDf(reqID, "[DOMAIN] After connection reset - Domain %s status: CurrentTestIndex=%d, TestsCompleted=%v, SuccessfulTestSet=%v",
			domain, domainStatus.CurrentTestIndex, domainStatus.TestsCompleted, domainStatus.SuccessfulTestSet)
	}

	s.logger.InfoWithRequestIDf(reqID, "[NEXT] Moving to next test for %s after connection reset: %s", domain, nextTest.GetTestTypeName())
}
