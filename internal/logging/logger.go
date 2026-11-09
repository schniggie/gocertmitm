package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Log levels reported to a Hook
const (
	LevelInfo    = "info"
	LevelError   = "error"
	LevelVerbose = "verbose"
	LevelDebug   = "debug"
)

// Hook receives every line that is written to the log at an enabled level.
// It is called synchronously and must not block or call back into the logger.
type Hook func(level, reqID, msg string)

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
	mu            sync.Mutex // Mutex to protect nextReqID
	hook          atomic.Pointer[Hook]
}

// SetHook installs (or, with nil, removes) a hook that observes log lines
func (l *Logger) SetHook(h Hook) {
	if h == nil {
		l.hook.Store(nil)
		return
	}
	l.hook.Store(&h)
}

// emit forwards a log line to the installed hook, if any
func (l *Logger) emit(level, reqID, format string, v []interface{}) {
	h := l.hook.Load()
	if h == nil {
		return
	}
	(*h)(level, reqID, fmt.Sprintf(format, v...))
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
	}, nil
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// Infof logs an info message
func (l *Logger) Infof(format string, v ...interface{}) {
	l.infoLogger.Printf(format, v...)
	l.emit(LevelInfo, "", format, v)
}

// InfoWithRequestIDf logs an info message with a request ID
func (l *Logger) InfoWithRequestIDf(reqID, format string, v ...interface{}) {
	l.infoLogger.Printf("[%s] "+format, append([]interface{}{reqID}, v...)...)
	l.emit(LevelInfo, reqID, format, v)
}

// Errorf logs an error message
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.errorLogger.Output(2, fmt.Sprintf(format, v...))
	l.emit(LevelError, "", format, v)
}

// ErrorWithRequestIDf logs an error message with a request ID
func (l *Logger) ErrorWithRequestIDf(reqID, format string, v ...interface{}) {
	l.errorLogger.Output(2, fmt.Sprintf("[%s] "+format, append([]interface{}{reqID}, v...)...))
	l.emit(LevelError, reqID, format, v)
}

// Verbosef logs a verbose message
func (l *Logger) Verbosef(format string, v ...interface{}) {
	if l.verbose {
		l.verboseLogger.Printf(format, v...)
		l.emit(LevelVerbose, "", format, v)
	}
}

// VerboseWithRequestIDf logs a verbose message with a request ID
func (l *Logger) VerboseWithRequestIDf(reqID, format string, v ...interface{}) {
	if l.verbose {
		l.verboseLogger.Printf("[%s] "+format, append([]interface{}{reqID}, v...)...)
		l.emit(LevelVerbose, reqID, format, v)
	}
}

// Debugf logs a debug message
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.debug {
		l.debugLogger.Output(2, fmt.Sprintf(format, v...))
		l.emit(LevelDebug, "", format, v)
	}
}

// DebugWithRequestIDf logs a debug message with a request ID
func (l *Logger) DebugWithRequestIDf(reqID, format string, v ...interface{}) {
	if l.debug {
		l.debugLogger.Output(2, fmt.Sprintf("[%s] "+format, append([]interface{}{reqID}, v...)...))
		l.emit(LevelDebug, reqID, format, v)
	}
}

// Fatalf logs a fatal message and exits
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.errorLogger.Output(2, fmt.Sprintf(format, v...))
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

// GetRequestID returns a unique request ID for logging
func (l *Logger) GetRequestID(clientIP, host string) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	reqID := fmt.Sprintf("REQ-%04X", l.nextReqID)
	l.nextReqID++

	return reqID
}
