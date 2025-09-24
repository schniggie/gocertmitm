package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/logging"
	"github.com/gocertmitm/internal/proxy"
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
	testType     = flag.String("testtype", "self-signed", "Test type: self-signed, replaced-key, real-cert, real-ca")
	autoTest     = flag.Bool("autotest", true, "Automatically test all methods for each domain")
	retrySeconds = flag.Int("retryseconds", 86400, "Time in seconds to wait before retesting a domain (default: 24 hours)")
	maxAttempts  = flag.Int("maxattempts", 1, "Maximum number of attempts for each test type before moving to the next test")
	webui        = flag.Bool("webui", false, "Enable the web UI")
	webuiAddr    = flag.String("webui-addr", ":8081", "Address to listen on for the web UI")
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

	// Initialize proxy server
	proxyServer, err := proxy.NewServer(*listenAddr, *listenAddrs, certManager, logger, time.Duration(*retrySeconds)*time.Second)
	if err != nil {
		logger.Fatalf("Failed to initialize proxy server: %v", err)
	}

	// Set the broadcaster on the logger
	logger.SetBroadcaster(proxyServer)

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

	// Start proxy server
	go func() {
		if err := proxyServer.Start(); err != nil {
			logger.Fatalf("Proxy server error: %v", err)
		}
	}()

	// Start web UI if enabled
	if *webui {
		go func() {
			logger.Infof("Starting web UI on %s", *webuiAddr)
			if err := proxyServer.StartWebUI(*webuiAddr); err != nil {
				logger.Fatalf("Web UI error: %v", err)
			}
		}()
	}

	logger.Infof("CertMITM proxy started, HTTP on %s, HTTPS on %s", *listenAddr, *listenAddrs)
	logger.Infof("Press Ctrl+C to stop")

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
	if err := proxyServer.Stop(); err != nil {
		logger.Errorf("Error stopping proxy server: %v", err)
	}
}
