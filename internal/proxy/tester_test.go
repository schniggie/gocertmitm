package proxy

import (
	"testing"
	"time"

	"github.com/gocertmitm/internal/certificates"
	"github.com/gocertmitm/internal/logging"
)

func newBareTester(t *testing.T) *Tester {
	t.Helper()
	t.Chdir(t.TempDir()) // the tester persists to ./data
	logger, err := logging.NewLogger(t.TempDir(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Close() })
	return NewTesterWithRetryPeriod(logger, certificates.SelfSigned, time.Hour, 1)
}

// main calls SetTestType (and therefore UpdateTestOrder) on every start;
// results loaded from disk must survive when the order did not change
func TestUpdateTestOrderKeepsResultsWhenUnchanged(t *testing.T) {
	tester := newBareTester(t)
	const d = "keep.example.com"
	tester.GetNextTest(d)
	tester.RecordTestResult(d, certificates.SelfSigned, true)

	tester.UpdateTestOrder(certificates.SelfSigned)
	if st := tester.GetTestStatus(d); !st.SuccessfulTestSet || st.SuccessfulTest != certificates.SelfSigned {
		t.Fatalf("results lost on unchanged order: %+v", st)
	}

	// A different order invalidates progress, including attempt counts
	tester.UpdateTestOrder(certificates.ReplacedKey)
	st := tester.GetTestStatus(d)
	if st.SuccessfulTestSet || len(st.TestResults) != 0 || len(st.AttemptCount) != 0 {
		t.Fatalf("expected full reset on changed order: %+v", st)
	}
}
