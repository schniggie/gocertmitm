package proxy

import (
	"sort"
	"time"

	"github.com/gocertmitm/internal/certificates"
)

// Domain verdicts exposed to observers (web UI, exports)
const (
	VerdictTesting    = "testing"    // tests still in progress
	VerdictVulnerable = "vulnerable" // the client accepted a forged certificate
	VerdictSecure     = "secure"     // every test was rejected; traffic is tunnelled
)

// Per-test states exposed to observers
const (
	TestStatePending  = "pending"  // not attempted yet
	TestStateCurrent  = "current"  // next certificate served for this domain
	TestStateAccepted = "accepted" // client completed a handshake with it
	TestStateRejected = "rejected" // client aborted the handshake
)

// TestTypeInfo describes a certificate test for observers
type TestTypeInfo struct {
	ID    int    `json:"id"`
	Key   string `json:"key"`
	Short string `json:"short"`
	Name  string `json:"name"`
}

// TestTypeKey returns a stable machine-friendly key for a test type
func TestTypeKey(t certificates.TestType) string {
	switch t {
	case certificates.SelfSigned:
		return "self-signed"
	case certificates.ReplacedKey:
		return "replaced-key"
	case certificates.RealCertificate:
		return "real-cert"
	case certificates.RealCertificateAsCA:
		return "real-ca"
	case certificates.Emudhra:
		return "emudhra"
	case certificates.EmudhraAAA:
		return "emudhra-aaa"
	case certificates.DirectTunnel:
		return "direct-tunnel"
	default:
		return "unknown"
	}
}

// testTypeShort returns a compact label for a test type
func testTypeShort(t certificates.TestType) string {
	switch t {
	case certificates.SelfSigned:
		return "Self-signed"
	case certificates.ReplacedKey:
		return "Replaced key"
	case certificates.RealCertificate:
		return "Wrong host"
	case certificates.RealCertificateAsCA:
		return "Leaf as CA"
	case certificates.Emudhra:
		return "eMudhra CA"
	case certificates.EmudhraAAA:
		return "eMudhra via AAA"
	case certificates.DirectTunnel:
		return "Tunnel"
	default:
		return "Unknown"
	}
}

// DescribeTestType returns observer metadata for a test type
func DescribeTestType(t certificates.TestType) TestTypeInfo {
	return TestTypeInfo{ID: int(t), Key: TestTypeKey(t), Short: testTypeShort(t), Name: t.GetTestTypeName()}
}

// TestView is the observed state of one certificate test for a domain
type TestView struct {
	Key      string `json:"key"`
	State    string `json:"state"`
	Attempts int    `json:"attempts"`
}

// DomainView is an immutable, JSON-friendly snapshot of a domain's state
type DomainView struct {
	Key            string     `json:"key"`    // key in the tester map (domain or IP)
	Domain         string     `json:"domain"` // hostname the status is attributed to
	IP             string     `json:"ip,omitempty"`
	IPs            []string   `json:"ips,omitempty"`
	Verdict        string     `json:"verdict"`
	AcceptedTest   string     `json:"accepted_test,omitempty"`
	CurrentTest    string     `json:"current_test,omitempty"`
	Tests          []TestView `json:"tests"`
	LastTested     time.Time  `json:"last_tested"`
	RetestDue      time.Time  `json:"retest_due"`
	TestsCompleted bool       `json:"tests_completed"`
}

// TesterConfig describes the tester configuration for observers
type TesterConfig struct {
	TestOrder    []TestTypeInfo `json:"test_order"`
	RetestPeriod string         `json:"retest_period"`
	MaxAttempts  int            `json:"max_attempts"`
}

// SetOnChange registers a callback invoked (outside the tester lock) with a
// fresh snapshot whenever a domain's state changes
func (t *Tester) SetOnChange(fn func(DomainView)) {
	t.mu.Lock()
	t.onChange = fn
	t.mu.Unlock()
}

// notifyChanged publishes the current snapshot of a domain to the
// registered observer. Must be called without holding t.mu.
func (t *Tester) notifyChanged(key string) {
	t.mu.RLock()
	fn := t.onChange
	status, ok := t.domains[key]
	var view DomainView
	if ok && fn != nil {
		view = t.viewLocked(key, status)
	}
	t.mu.RUnlock()

	if ok && fn != nil {
		fn(view)
	}
}

// viewLocked builds a DomainView; the caller must hold t.mu (read or write)
func (t *Tester) viewLocked(key string, s *DomainTestStatus) DomainView {
	v := DomainView{
		Key:            key,
		Domain:         s.Domain,
		IP:             s.IP,
		IPs:            append([]string(nil), s.IPs...),
		LastTested:     s.LastTested,
		RetestDue:      s.LastTested.Add(t.retestPeriod),
		TestsCompleted: s.TestsCompleted,
		Tests:          make([]TestView, 0, len(t.testOrder)),
	}

	switch {
	case s.SuccessfulTestSet:
		v.Verdict = VerdictVulnerable
		v.AcceptedTest = TestTypeKey(s.SuccessfulTest)
	case s.TestsCompleted:
		v.Verdict = VerdictSecure
	default:
		v.Verdict = VerdictTesting
		if s.CurrentTestIndex >= 0 && s.CurrentTestIndex < len(t.testOrder) {
			v.CurrentTest = TestTypeKey(t.testOrder[s.CurrentTestIndex])
		}
	}

	for _, tt := range t.testOrder {
		tv := TestView{Key: TestTypeKey(tt), State: TestStatePending, Attempts: s.AttemptCount[tt]}
		if result, tried := s.TestResults[tt]; tried {
			if result {
				tv.State = TestStateAccepted
			} else {
				tv.State = TestStateRejected
			}
		} else if v.CurrentTest == tv.Key {
			tv.State = TestStateCurrent
		}
		v.Tests = append(v.Tests, tv)
	}

	return v
}

// Snapshot returns views of all domains, most recently tested first
func (t *Tester) Snapshot() []DomainView {
	t.mu.RLock()
	views := make([]DomainView, 0, len(t.domains))
	for key, status := range t.domains {
		views = append(views, t.viewLocked(key, status))
	}
	t.mu.RUnlock()

	sort.Slice(views, func(i, j int) bool {
		if !views[i].LastTested.Equal(views[j].LastTested) {
			return views[i].LastTested.After(views[j].LastTested)
		}
		return views[i].Key < views[j].Key
	})
	return views
}

// View returns the snapshot of a single domain
func (t *Tester) View(key string) (DomainView, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	status, ok := t.domains[key]
	if !ok {
		return DomainView{}, false
	}
	return t.viewLocked(key, status), true
}

// Config returns the tester configuration
func (t *Tester) Config() TesterConfig {
	t.mu.RLock()
	defer t.mu.RUnlock()
	order := make([]TestTypeInfo, 0, len(t.testOrder))
	for _, tt := range t.testOrder {
		order = append(order, DescribeTestType(tt))
	}
	return TesterConfig{TestOrder: order, RetestPeriod: t.retestPeriod.String(), MaxAttempts: t.maxAttempts}
}

// ResetDomain clears all recorded results for a domain so the full test
// sequence runs again on the next connection. It returns the IPs associated
// with the domain so callers can clear per-IP state too.
func (t *Tester) ResetDomain(key string) ([]string, bool) {
	t.mu.Lock()
	status, ok := t.domains[key]
	var ips []string
	if ok {
		status.CurrentTestIndex = 0
		status.TestResults = make(map[certificates.TestType]bool)
		status.AttemptCount = make(map[certificates.TestType]int)
		status.TestsCompleted = false
		status.SuccessfulTestSet = false
		status.SuccessfulTest = 0
		status.LastTested = time.Now()
		ips = append(ips, t.domainToIPs[key]...)
		t.dirty = true
	}
	t.mu.Unlock()

	if ok {
		t.logger.Infof("[WEBUI] Reset test state for %s", key)
		t.notifyChanged(key)
	}
	return ips, ok
}

// DeleteDomain forgets a domain and its IP mappings entirely. It returns the
// IPs that were associated with it.
func (t *Tester) DeleteDomain(key string) ([]string, bool) {
	t.mu.Lock()
	_, ok := t.domains[key]
	var ips []string
	if ok {
		delete(t.domains, key)
		ips = append(ips, t.domainToIPs[key]...)
		delete(t.domainToIPs, key)
		for ip, d := range t.ipToDomain {
			if d == key {
				delete(t.ipToDomain, ip)
			}
		}
		t.dirty = true
	}
	t.mu.Unlock()

	if ok {
		t.logger.Infof("[WEBUI] Deleted test state for %s", key)
	}
	return ips, ok
}
