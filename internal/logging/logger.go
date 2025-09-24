package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Broadcaster defines the interface for broadcasting messages
type Broadcaster interface {
	Broadcast(message []byte)
}

// Logger provides logging functionality
type Logger struct {
	infoLogger    *log.Logger
	errorLogger   *log.Logger
	verboseLogger *log.Logger
	debugLogger   *log.Logger
	verbose       bool
	debug         bool
	logFile       *os.File
	nextReqID     uint64
	reqIDMap      map[string]string // Maps clientIP:host to request ID
	mu            sync.Mutex        // Mutex to protect concurrent access to reqIDMap and nextReqID
	broadcaster   Broadcaster
}

// NewLogger creates a new logger
func NewLogger(logDir string, verbose bool, debug bool) (*Logger, error) {
	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create log file
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logPath := filepath.Join(logDir, fmt.Sprintf("certmitm_%s.log", timestamp))
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %v", err)
	}

	// Create multi-writer for console and file
	infoWriter := io.MultiWriter(os.Stdout, logFile)
	errorWriter := io.MultiWriter(os.Stderr, logFile)

	// Verbose logger writes to stdout only when verbose mode is enabled
	verboseWriter := io.MultiWriter(logFile)
	if verbose {
		verboseWriter = io.MultiWriter(os.Stdout, logFile)
	}

	// Debug logger writes to stdout only when debug mode is enabled
	debugWriter := io.MultiWriter(logFile)
	if debug {
		debugWriter = io.MultiWriter(os.Stdout, logFile)
	}

	// Create loggers
	infoLogger := log.New(infoWriter, "INFO: ", log.Ldate|log.Ltime)
	errorLogger := log.New(errorWriter, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	verboseLogger := log.New(verboseWriter, "VERBOSE: ", log.Ldate|log.Ltime)
	debugLogger := log.New(debugWriter, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)

	return &Logger{
		infoLogger:    infoLogger,
		errorLogger:   errorLogger,
		verboseLogger: verboseLogger,
		debugLogger:   debugLogger,
		verbose:       verbose,
		debug:         debug,
		logFile:       logFile,
		nextReqID:     1,
		reqIDMap:      make(map[string]string),
	}, nil
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// SetBroadcaster sets the broadcaster for the logger
func (l *Logger) SetBroadcaster(b Broadcaster) {
	l.broadcaster = b
}

// Infof logs an info message
func (l *Logger) Infof(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.infoLogger.Print(msg)
	if l.broadcaster != nil {
		logEntry := map[string]string{"type": "log", "message": msg}
		jsonEntry, _ := json.Marshal(logEntry)
		l.broadcaster.Broadcast(jsonEntry)
	}
}

// InfoWithRequestIDf logs an info message with a request ID
func (l *Logger) InfoWithRequestIDf(reqID, format string, v ...interface{}) {
	msg := fmt.Sprintf("[%s] "+format, append([]interface{}{reqID}, v...)...)
	l.infoLogger.Print(msg)
	if l.broadcaster != nil {
		logEntry := map[string]string{"type": "log", "message": msg}
		jsonEntry, _ := json.Marshal(logEntry)
		l.broadcaster.Broadcast(jsonEntry)
	}
}

// Errorf logs an error message
func (l *Logger) Errorf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.errorLogger.Print(msg)
	if l.broadcaster != nil {
		logEntry := map[string]string{"type": "log", "message": msg}
		jsonEntry, _ := json.Marshal(logEntry)
		l.broadcaster.Broadcast(jsonEntry)
	}
}

// ErrorWithRequestIDf logs an error message with a request ID
func (l *Logger) ErrorWithRequestIDf(reqID, format string, v ...interface{}) {
	msg := fmt.Sprintf("[%s] "+format, append([]interface{}{reqID}, v...)...)
	l.errorLogger.Print(msg)
	if l.broadcaster != nil {
		logEntry := map[string]string{"type": "log", "message": msg}
		jsonEntry, _ := json.Marshal(logEntry)
		l.broadcaster.Broadcast(jsonEntry)
	}
}

// Verbosef logs a verbose message
func (l *Logger) Verbosef(format string, v ...interface{}) {
	if l.verbose {
		msg := fmt.Sprintf(format, v...)
		l.verboseLogger.Print(msg)
		if l.broadcaster != nil {
			logEntry := map[string]string{"type": "log", "message": msg}
			jsonEntry, _ := json.Marshal(logEntry)
			l.broadcaster.Broadcast(jsonEntry)
		}
	}
}

// VerboseWithRequestIDf logs a verbose message with a request ID
func (l *Logger) VerboseWithRequestIDf(reqID, format string, v ...interface{}) {
	if l.verbose {
		msg := fmt.Sprintf("[%s] "+format, append([]interface{}{reqID}, v...)...)
		l.verboseLogger.Print(msg)
		if l.broadcaster != nil {
			logEntry := map[string]string{"type": "log", "message": msg}
			jsonEntry, _ := json.Marshal(logEntry)
			l.broadcaster.Broadcast(jsonEntry)
		}
	}
}

// Debugf logs a debug message
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.debug {
		msg := fmt.Sprintf(format, v...)
		l.debugLogger.Print(msg)
		if l.broadcaster != nil {
			logEntry := map[string]string{"type": "log", "message": msg}
			jsonEntry, _ := json.Marshal(logEntry)
			l.broadcaster.Broadcast(jsonEntry)
		}
	}
}

// DebugWithRequestIDf logs a debug message with a request ID
func (l *Logger) DebugWithRequestIDf(reqID, format string, v ...interface{}) {
	if l.debug {
		msg := fmt.Sprintf("[%s] "+format, append([]interface{}{reqID}, v...)...)
		l.debugLogger.Print(msg)
		if l.broadcaster != nil {
			logEntry := map[string]string{"type": "log", "message": msg}
			jsonEntry, _ := json.Marshal(logEntry)
			l.broadcaster.Broadcast(jsonEntry)
		}
	}
}

// Fatalf logs a fatal message and exits
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.errorLogger.Printf(format, v...)
	os.Exit(1)
}

// LogRequest logs an HTTP request
func (l *Logger) LogRequest(clientIP, method, host, path string, isSecure bool) {
	protocol := "HTTP"
	if isSecure {
		protocol = "HTTPS"
	}

	// Get or generate a request ID
	reqID := l.GetRequestID(clientIP, host)

	l.Infof("[%s][%s] %s %s %s from %s", reqID, protocol, method, host, path, clientIP)
	l.Debugf("[%s] Full request: %s %s %s%s from %s", reqID, protocol, method, host, path, clientIP)
}

// LogCertificateTest logs a certificate test
func (l *Logger) LogCertificateTest(clientIP, host string, testType string, accepted bool) {
	result := "REJECTED"
	if accepted {
		result = "ACCEPTED"
	}
	reqID := l.GetRequestID(clientIP, host)
	// Log at debug level instead of info level to reduce verbosity
	l.Debugf("[%s][CERT] %s test for %s from %s: %s", reqID, testType, host, clientIP, result)
}

// LogConnectionSummary logs a summary of a connection at the end
func (l *Logger) LogConnectionSummary(clientIP, host string, testType string, accepted bool, directTunnel bool) {
	reqID := l.GetRequestID(clientIP, host)

	if directTunnel {
		l.Infof("[%s][SUMMARY] Connection from %s to %s: Direct tunnel mode (all tests failed)",
			reqID, clientIP, host)
		return
	}

	result := "REJECTED"
	if accepted {
		result = "ACCEPTED"
	}

	l.Infof("[%s][SUMMARY] Connection from %s to %s: %s test %s",
		reqID, clientIP, host, testType, result)
}

// GetRequestID returns a request ID for a client IP and host
// Always generates a new unique request ID for each call
func (l *Logger) GetRequestID(clientIP, host string) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := clientIP + ":" + host

	// Generate a new request ID
	reqID := fmt.Sprintf("REQ-%04X", l.nextReqID)
	l.nextReqID++

	// Store the request ID
	l.reqIDMap[key] = reqID

	return reqID
}

// ClearRequestID removes a request ID for a client IP and host
func (l *Logger) ClearRequestID(clientIP, host string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := clientIP + ":" + host
	delete(l.reqIDMap, key)
}
