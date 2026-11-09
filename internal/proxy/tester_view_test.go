package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/logging"
)

func newTestTester(t *testing.T) *Tester {
	t.Helper()
	t.Chdir(t.TempDir()) // the tester persists to ./data
	logger, err := logging.NewLogger(t.TempDir(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Close() })
	return NewTesterWithRetryPeriod(logger, certificates.SelfSigned, time.Hour, 1)
}

func testState(v DomainView, key string) string {
	for _, tv := range v.Tests {
		if tv.Key == key {
			return tv.State
		}
	}
	return ""
}

func TestDomainViewLifecycle(t *testing.T) {
	tester := newTestTester(t)

	var mu sync.Mutex
	var seen []DomainView
	tester.SetOnChange(func(v DomainView) {
		// Re-entering the tester must not deadlock: the callback runs unlocked
		_ = tester.Snapshot()
		mu.Lock()
		seen = append(seen, v)
		mu.Unlock()
	})

	const d = "app.example.com"
	if got := tester.GetNextTest(d); got != certificates.SelfSigned {
		t.Fatalf("first test = %v", got)
	}
	v, ok := tester.View(d)
	if !ok || v.Verdict != VerdictTesting || v.CurrentTest != "self-signed" || testState(v, "self-signed") != TestStateCurrent {
		t.Fatalf("initial view: %+v", v)
	}

	tester.RecordTestResult(d, certificates.SelfSigned, false)
	v, _ = tester.View(d)
	if testState(v, "self-signed") != TestStateRejected || testState(v, "replaced-key") != TestStateCurrent {
		t.Fatalf("after rejection: %+v", v.Tests)
	}

	tester.RecordTestResult(d, certificates.ReplacedKey, true)
	v, _ = tester.View(d)
	if v.Verdict != VerdictVulnerable || v.AcceptedTest != "replaced-key" || testState(v, "replaced-key") != TestStateAccepted {
		t.Fatalf("after acceptance: %+v", v)
	}

	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 3 {
		t.Fatalf("expected 3 change notifications (new, reject, accept), got %d", n)
	}

	// Reset clears results and restarts the sequence
	if _, ok := tester.ResetDomain(d); !ok {
		t.Fatal("reset failed")
	}
	v, _ = tester.View(d)
	if v.Verdict != VerdictTesting || v.AcceptedTest != "" || testState(v, "self-signed") != TestStateCurrent {
		t.Fatalf("after reset: %+v", v)
	}

	if _, ok := tester.DeleteDomain(d); !ok {
		t.Fatal("delete failed")
	}
	if _, ok := tester.View(d); ok {
		t.Fatal("domain still present after delete")
	}
	if _, ok := tester.ResetDomain(d); ok {
		t.Fatal("reset of deleted domain succeeded")
	}
}

func TestAllRejectedIsSecure(t *testing.T) {
	tester := newTestTester(t)
	const d = "pinned.example.com"
	tester.GetNextTest(d)
	for _, tt := range tester.GetTestOrder() {
		tester.RecordTestResult(d, tt, false)
	}
	v, _ := tester.View(d)
	if v.Verdict != VerdictSecure || !v.TestsCompleted {
		t.Fatalf("expected secure verdict: %+v", v)
	}
	for _, tv := range v.Tests {
		if tv.State != TestStateRejected {
			t.Fatalf("expected all rejected: %+v", v.Tests)
		}
	}
}
