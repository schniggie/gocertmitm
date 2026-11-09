package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/events"
	"github.com/gocertmitm/internal/logging"
	"github.com/gocertmitm/internal/proxy"
	"github.com/gocertmitm/internal/webui"
)

var (
	listenAddr   = flag.String("listen", ":8080", "Address to listen on for HTTP proxy")
	listenAddrs  = flag.String("listens", ":8443", "Address to listen on for HTTPS proxy")
	verbose      = flag.Bool("verbose", false, "Enable verbose logging (operational details)")
	debug        = flag.Bool("debug", false, "Enable debug logging (developer information)")
	certDir      = flag.String("certdir", "./certs", "Directory to store generated certificates")
	logDir       = flag.String("logdir", "./logs", "Directory to store logs")
	payloadDir   = flag.String("payloaddir", "./payloads", "Directory to store request/response payloads")
	savePayloads = flag.Bool("savepayloads", true, "Enable saving of request/response payloads")
	testType     = flag.String("testtype", "self-signed", "Test type: self-signed, replaced-key, real-cert, real-ca, emudhra")
	autoTest     = flag.Bool("autotest", true, "Automatically test all methods for each domain")
	retrySeconds = flag.Int("retryseconds", 86400, "Time in seconds to wait before retesting a domain (default: 24 hours)")
	maxAttempts  = flag.Int("maxattempts", 1, "Maximum number of attempts for each test type before moving to the next test")
	emudhraChain = flag.String("emudhra-chain", "both", "Compromised eMudhra chain to serve: modern, old or both")
	webUI        = flag.Bool("webui", false, "Enable the web interface")
	webUIAddr    = flag.String("webui-addr", "127.0.0.1:8081", "Address for the web interface (keep it off untrusted networks)")
	webUIToken   = flag.String("webui-token", "", "Web interface access token (default: $CERTMITM_WEBUI_TOKEN, else randomly generated)")
	webUINoAuth  = flag.Bool("webui-noauth", false, "Disable web interface authentication (only IP-literal/localhost Host headers are accepted)")
)

func main() {
	flag.Parse()

	// Initialize logger
	logger, err := logging.NewLogger(*logDir, *verbose, *debug)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Close()

	// Log startup information
	logger.Infof("Starting GoCertMITM with verbose=%v, debug=%v", *verbose, *debug)

	// Initialize certificate manager
	certManager, err := certificates.NewManager(*certDir, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize certificate manager: %v", err)
	}

	// Select the compromised eMudhra chain variant to serve
	if err := certManager.SetEmudhraChainMode(*emudhraChain); err != nil {
		logger.Fatalf("Invalid eMudhra chain mode: %v", err)
	}
	logger.Infof("eMudhra chain mode: %s", *emudhraChain)

	// Initialize proxy server
	proxyServer, err := proxy.NewServer(*listenAddr, *listenAddrs, certManager, logger, time.Duration(*retrySeconds)*time.Second)
	if err != nil {
		logger.Fatalf("Failed to initialize proxy server: %v", err)
	}

	// Set the max attempts for each test type
	proxyServer.SetMaxAttempts(*maxAttempts)

	// Configure payload logging
	if err := proxyServer.SetPayloadDir(*payloadDir); err != nil {
		logger.Fatalf("Failed to set payload directory: %v", err)
	}
	proxyServer.SetSavePayloads(*savePayloads)

	if *savePayloads {
		logger.Infof("Saving request/response payloads to %s", *payloadDir)
	} else {
		logger.Infof("Request/response payload saving is disabled")
	}

	// Parse the test type
	var selectedTestType certificates.TestType
	switch *testType {
	case "self-signed":
		selectedTestType = certificates.SelfSigned
	case "replaced-key":
		selectedTestType = certificates.ReplacedKey
	case "real-cert":
		selectedTestType = certificates.RealCertificate
	case "real-ca":
		selectedTestType = certificates.RealCertificateAsCA
	case "emudhra":
		selectedTestType = certificates.Emudhra
	default:
		logger.Fatalf("Invalid test type: %s", *testType)
	}

	// Set test type first (this will be used as the default if auto-test is disabled)
	proxyServer.SetTestType(selectedTestType)

	// Then set auto-test mode (this will override the certificate function if enabled)
	proxyServer.SetAutoTest(*autoTest)

	// Log auto-test status
	if *autoTest {
		logger.Infof("Auto-testing enabled - will try all test types for each domain")
	} else {
		logger.Infof("Auto-testing disabled - using fixed test type: %s", *testType)
	}

	// Start the web interface before the proxy so no early events are missed
	var ui *webui.Server
	if *webUI {
		ui, err = startWebUI(proxyServer, logger)
		if err != nil {
			logger.Fatalf("Failed to start web UI: %v", err)
		}
	}

	// Start proxy server
	go func() {
		if err := proxyServer.Start(); err != nil {
			logger.Fatalf("Proxy server error: %v", err)
		}
	}()

	logger.Infof("CertMITM proxy started, HTTP on %s, HTTPS on %s", *listenAddr, *listenAddrs)
	logger.Infof("Press Ctrl+C to stop")

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
	if ui != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := ui.Shutdown(ctx); err != nil {
			logger.Errorf("Error stopping web UI: %v", err)
		}
		cancel()
	}
	if err := proxyServer.Stop(); err != nil {
		logger.Errorf("Error stopping proxy server: %v", err)
	}
}

// logLine is the payload of log events streamed to the web UI
type logLine struct {
	Level string `json:"level"`
	ReqID string `json:"req_id,omitempty"`
	Msg   string `json:"msg"`
}

// startWebUI wires the event bus into the proxy and logger and starts the
// web interface listener
func startWebUI(proxyServer *proxy.Server, logger *logging.Logger) (*webui.Server, error) {
	bus := events.NewBus(
		events.WithHistory(events.TopicLog, 3000),
		events.WithHistory(events.TopicRequest, 2000),
		events.WithHistory(events.TopicHandshake, 1000),
		events.WithHistory(events.TopicDomain, 500),
		events.WithSubscriberBuffer(2048),
	)
	proxyServer.SetEventBus(bus)
	logger.SetHook(func(level, reqID, msg string) {
		bus.Publish(events.TopicLog, logLine{Level: level, ReqID: reqID, Msg: msg})
	})

	token := *webUIToken
	if token == "" {
		token = os.Getenv("CERTMITM_WEBUI_TOKEN")
	}
	generated := false
	if token == "" && !*webUINoAuth {
		var err error
		if token, err = webui.GenerateToken(); err != nil {
			return nil, fmt.Errorf("generate access token: %w", err)
		}
		generated = true
	}

	ui, err := webui.New(webui.Config{
		Addr:    *webUIAddr,
		Token:   token,
		NoAuth:  *webUINoAuth,
		Backend: proxyServer,
		Bus:     bus,
		Logger:  logger,
	})
	if err != nil {
		return nil, err
	}

	// Bind synchronously so address errors surface at startup
	ln, err := net.Listen("tcp", *webUIAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := ui.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Errorf("Web UI error: %v", err)
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + "/"
	switch {
	case *webUINoAuth:
		logger.Infof("Web UI listening on %s (authentication DISABLED)", url)
	case generated:
		// Printed to the console only; not written to the log file or UI stream
		logger.Infof("Web UI listening on %s (access token generated, see console)", url)
		fmt.Printf("\n  Web UI: %s?token=%s\n\n", url, token)
	default:
		logger.Infof("Web UI listening on %s (token authentication)", url)
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		logger.Infof("Web UI is reachable from the network; captured payloads may contain credentials")
	}
	return ui, nil
}
