package logging

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// sanitizePathComponent makes a user-controlled string (such as the HTTP Host
// header) safe to use as a directory name so it cannot traverse outside the
// payload directory
func sanitizePathComponent(name string) string {
	if name == "" {
		return "unknown-host"
	}
	s := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 || r < 32 || r == 127 {
			return '_'
		}
		return r
	}, name)
	switch s {
	case ".", "..":
		return "unknown-host"
	}
	return s
}

// PayloadLogger handles logging of HTTP request and response payloads
type PayloadLogger struct {
	baseDir string
	mu      sync.Mutex
}

// NewPayloadLogger creates a new payload logger
func NewPayloadLogger(baseDir string) (*PayloadLogger, error) {
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create payload directory: %v", err)
	}

	return &PayloadLogger{
		baseDir: baseDir,
	}, nil
}

// LogRequest logs an HTTP request payload
func (p *PayloadLogger) LogRequest(clientIP, host string, req *http.Request, reqID ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Create domain directory if it doesn't exist
	domainDir := filepath.Join(p.baseDir, sanitizePathComponent(host))
	if err := os.MkdirAll(domainDir, 0700); err != nil {
		return fmt.Errorf("failed to create domain directory: %v", err)
	}

	// Create timestamp for filename
	timestamp := time.Now().Format("20060102_150405.000")

	// Use request ID in filename if provided
	var filenamePrefix string
	if len(reqID) > 0 && reqID[0] != "" {
		filenamePrefix = fmt.Sprintf("req_%s_%s", timestamp, reqID[0])
	} else {
		filenamePrefix = fmt.Sprintf("req_%s_%s", timestamp, clientIP)
	}

	// Create request metadata file
	metadataPath := filepath.Join(domainDir, filenamePrefix+".meta")
	metadataFile, err := os.OpenFile(metadataPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create request metadata file: %v", err)
	}
	defer metadataFile.Close()

	// Write request metadata
	fmt.Fprintf(metadataFile, "Time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(metadataFile, "Client IP: %s\n", clientIP)
	if len(reqID) > 0 && reqID[0] != "" {
		fmt.Fprintf(metadataFile, "Request ID: %s\n", reqID[0])
	}
	fmt.Fprintf(metadataFile, "Method: %s\n", req.Method)
	fmt.Fprintf(metadataFile, "Host: %s\n", host)
	fmt.Fprintf(metadataFile, "Path: %s\n", req.URL.Path)
	fmt.Fprintf(metadataFile, "Protocol: %s\n", req.Proto)
	fmt.Fprintf(metadataFile, "Headers:\n")
	for key, values := range req.Header {
		for _, value := range values {
			fmt.Fprintf(metadataFile, "  %s: %s\n", key, value)
		}
	}

	// If request has a body, save it
	if req.Body != nil {
		// Create a copy of the body
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %v", err)
		}

		// Restore the body for further processing
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Create body file
		bodyPath := filepath.Join(domainDir, filenamePrefix+".body")
		bodyFile, err := os.OpenFile(bodyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("failed to create request body file: %v", err)
		}
		defer bodyFile.Close()

		// Write body
		if _, err := bodyFile.Write(bodyBytes); err != nil {
			return fmt.Errorf("failed to write request body: %v", err)
		}

		// Add body info to metadata
		fmt.Fprintf(metadataFile, "Body Size: %d bytes\n", len(bodyBytes))
		fmt.Fprintf(metadataFile, "Body File: %s\n", filepath.Base(bodyPath))
	} else {
		fmt.Fprintf(metadataFile, "Body: None\n")
	}

	return nil
}

// LogResponse logs an HTTP response payload
func (p *PayloadLogger) LogResponse(clientIP, host string, resp *http.Response, reqID ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Create domain directory if it doesn't exist
	domainDir := filepath.Join(p.baseDir, sanitizePathComponent(host))
	if err := os.MkdirAll(domainDir, 0700); err != nil {
		return fmt.Errorf("failed to create domain directory: %v", err)
	}

	// Create timestamp for filename
	timestamp := time.Now().Format("20060102_150405.000")

	// Use request ID in filename if provided
	var filenamePrefix string
	if len(reqID) > 0 && reqID[0] != "" {
		filenamePrefix = fmt.Sprintf("resp_%s_%s", timestamp, reqID[0])
	} else {
		filenamePrefix = fmt.Sprintf("resp_%s_%s", timestamp, clientIP)
	}

	// Create response metadata file
	metadataPath := filepath.Join(domainDir, filenamePrefix+".meta")
	metadataFile, err := os.OpenFile(metadataPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create response metadata file: %v", err)
	}
	defer metadataFile.Close()

	// Write response metadata
	fmt.Fprintf(metadataFile, "Time: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(metadataFile, "Client IP: %s\n", clientIP)
	if len(reqID) > 0 && reqID[0] != "" {
		fmt.Fprintf(metadataFile, "Request ID: %s\n", reqID[0])
	}
	fmt.Fprintf(metadataFile, "Status: %s\n", resp.Status)
	fmt.Fprintf(metadataFile, "Protocol: %s\n", resp.Proto)
	fmt.Fprintf(metadataFile, "Headers:\n")
	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Fprintf(metadataFile, "  %s: %s\n", key, value)
		}
	}

	// If response has a body, save it
	if resp.Body != nil {
		// Create a copy of the body
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}

		// Restore the body for further processing
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Create body file
		bodyPath := filepath.Join(domainDir, filenamePrefix+".body")
		bodyFile, err := os.OpenFile(bodyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("failed to create response body file: %v", err)
		}
		defer bodyFile.Close()

		// Write body
		if _, err := bodyFile.Write(bodyBytes); err != nil {
			return fmt.Errorf("failed to write response body: %v", err)
		}

		// Add body info to metadata
		fmt.Fprintf(metadataFile, "Body Size: %d bytes\n", len(bodyBytes))
		fmt.Fprintf(metadataFile, "Body File: %s\n", filepath.Base(bodyPath))
	} else {
		fmt.Fprintf(metadataFile, "Body: None\n")
	}

	return nil
}
