package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"sort"
	"sync/atomic"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/events"
)

// RequestEvent describes one request relayed by the proxy
type RequestEvent struct {
	ReqID       string  `json:"req_id"`
	ClientIP    string  `json:"client_ip"`
	Method      string  `json:"method"`
	Scheme      string  `json:"scheme"` // "https" for decrypted MITM traffic
	Host        string  `json:"host"`
	Path        string  `json:"path"`
	Query       string  `json:"query,omitempty"`
	Status      int     `json:"status"`
	ReqBytes    int     `json:"req_bytes"`
	RespBytes   int     `json:"resp_bytes"`
	ContentType string  `json:"content_type,omitempty"`
	DurationMs  float64 `json:"duration_ms"`
	TestType    string  `json:"test_type,omitempty"` // certificate the client accepted
	Saved       bool    `json:"saved"`               // payload written to disk
	Error       string  `json:"error,omitempty"`
}

// HandshakeEvent describes a TLS handshake a client aborted
type HandshakeEvent struct {
	ReqID    string `json:"req_id"`
	ClientIP string `json:"client_ip"`
	SNI      string `json:"sni"`
	TestType string `json:"test_type"`
	Error    string `json:"error"`
}

// serverCounters holds monotonic counters exposed to observers
type serverCounters struct {
	requests          atomic.Uint64
	mitmRequests      atomic.Uint64
	requestErrors     atomic.Uint64
	handshakeFailures atomic.Uint64
}

// Stats is a point-in-time view of server activity
type Stats struct {
	StartTime         time.Time      `json:"start_time"`
	Requests          uint64         `json:"requests"`
	MITMRequests      uint64         `json:"mitm_requests"`
	RequestErrors     uint64         `json:"request_errors"`
	HandshakeFailures uint64         `json:"handshake_failures"`
	ActiveClients     map[string]int `json:"active_clients"`
	Domains           int            `json:"domains"`
	Vulnerable        int            `json:"vulnerable"`
	Secure            int            `json:"secure"`
	Testing           int            `json:"testing"`
}

// CAInfo describes the CA generated for the self-signed tests
type CAInfo struct {
	Subject           string    `json:"subject"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	SHA256Fingerprint string    `json:"sha256_fingerprint"`
}

// Info describes the static server configuration
type Info struct {
	HTTPAddr     string         `json:"http_addr"`
	HTTPSAddr    string         `json:"https_addr"`
	AutoTest     bool           `json:"auto_test"`
	FixedTest    string         `json:"fixed_test"`
	SavePayloads bool           `json:"save_payloads"`
	PayloadDir   string         `json:"payload_dir"`
	Tester       TesterConfig   `json:"tester"`
	TestTypes    []TestTypeInfo `json:"test_types"`
	CA           *CAInfo        `json:"ca,omitempty"`
}

// SetEventBus attaches an observer bus. Must be called before Start.
func (s *Server) SetEventBus(bus *events.Bus) {
	s.events = bus
	if bus == nil {
		s.tester.SetOnChange(nil)
		return
	}
	s.tester.SetOnChange(func(v DomainView) {
		bus.Publish(events.TopicDomain, v)
	})
}

func (s *Server) publishRequest(evt RequestEvent) {
	s.stats.requests.Add(1)
	if evt.Scheme == "https" {
		s.stats.mitmRequests.Add(1)
	}
	if evt.Error != "" {
		s.stats.requestErrors.Add(1)
	}
	s.events.Publish(events.TopicRequest, evt)
}

func (s *Server) publishHandshakeFailure(evt HandshakeEvent) {
	s.stats.handshakeFailures.Add(1)
	s.events.Publish(events.TopicHandshake, evt)
}

// Domains returns a snapshot of every tested domain
func (s *Server) Domains() []DomainView {
	return s.tester.Snapshot()
}

// Domain returns the snapshot of one domain
func (s *Server) Domain(key string) (DomainView, bool) {
	return s.tester.View(key)
}

// forgetProxyState clears the per-domain proxy state that would otherwise
// keep a domain pinned in direct tunnel mode
func (s *Server) forgetProxyState(key string, ips []string) {
	s.directTunnelMu.Lock()
	delete(s.directTunnelDomains, key)
	for _, ip := range ips {
		delete(s.directTunnelDomains, ip)
	}
	s.directTunnelMu.Unlock()

	s.handshakesMu.Lock()
	delete(s.failedHandshakes, key)
	s.handshakesMu.Unlock()
}

// ResetDomain re-runs the full test sequence for a domain on its next
// connection
func (s *Server) ResetDomain(key string) bool {
	ips, ok := s.tester.ResetDomain(key)
	if ok {
		s.forgetProxyState(key, ips)
	}
	return ok
}

// DeleteDomain forgets a domain entirely
func (s *Server) DeleteDomain(key string) bool {
	ips, ok := s.tester.DeleteDomain(key)
	if ok {
		s.forgetProxyState(key, ips)
		s.events.Publish(events.TopicDomain, DomainView{Key: key, Verdict: "deleted"})
	}
	return ok
}

// Stats returns current activity counters
func (s *Server) Stats() Stats {
	st := Stats{
		StartTime:         s.startTime,
		Requests:          s.stats.requests.Load(),
		MITMRequests:      s.stats.mitmRequests.Load(),
		RequestErrors:     s.stats.requestErrors.Load(),
		HandshakeFailures: s.stats.handshakeFailures.Load(),
		ActiveClients:     make(map[string]int),
	}

	s.connectionMu.Lock()
	for ip, n := range s.connections {
		st.ActiveClients[ip] = n
	}
	s.connectionMu.Unlock()

	for _, d := range s.tester.Snapshot() {
		st.Domains++
		switch d.Verdict {
		case VerdictVulnerable:
			st.Vulnerable++
		case VerdictSecure:
			st.Secure++
		default:
			st.Testing++
		}
	}
	return st
}

// Info returns the static server configuration
func (s *Server) Info() Info {
	info := Info{
		HTTPAddr:     s.httpAddr,
		HTTPSAddr:    s.httpsAddr,
		AutoTest:     s.autoTest,
		FixedTest:    TestTypeKey(s.testType),
		SavePayloads: s.savePayloads,
		PayloadDir:   s.payloadDir,
		Tester:       s.tester.Config(),
	}

	types := []certificates.TestType{
		certificates.SelfSigned,
		certificates.ReplacedKey,
		certificates.RealCertificate,
		certificates.RealCertificateAsCA,
		certificates.Emudhra,
		certificates.EmudhraAAA,
		certificates.DirectTunnel,
	}
	for _, t := range types {
		info.TestTypes = append(info.TestTypes, DescribeTestType(t))
	}
	sort.SliceStable(info.TestTypes, func(i, j int) bool { return info.TestTypes[i].ID < info.TestTypes[j].ID })

	if ca := s.certManager.CA; ca != nil && ca.Certificate != nil {
		sum := sha256.Sum256(ca.Certificate.Raw)
		info.CA = &CAInfo{
			Subject:           ca.Certificate.Subject.String(),
			NotBefore:         ca.Certificate.NotBefore,
			NotAfter:          ca.Certificate.NotAfter,
			SHA256Fingerprint: hex.EncodeToString(sum[:]),
		}
	}
	return info
}

// CACertificatePEM returns the PEM-encoded public CA certificate
func (s *Server) CACertificatePEM() []byte {
	ca := s.certManager.CA
	if ca == nil || ca.Certificate == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate.Raw})
}

// PayloadDir returns the directory request/response payloads are saved to
func (s *Server) PayloadDir() string {
	return s.payloadDir
}
