package bench

import (
	"testing"

	"cloak/internal/detect"
)

// TestLeakCorpusAllCasesPass turns the leak corpus into a regression gate:
// a future rule change that misses a planted secret or introduces a false
// positive fails `go test` here, not just a manual `cloak bench` run.
func TestLeakCorpusAllCasesPass(t *testing.T) {
	report := Run(detect.New(), Corpus(), 1) // 1 iteration: latency isn't relevant to this test
	for _, res := range report.Results {
		if !res.Passed() {
			t.Errorf("case %q failed: missed=%v falsePositive=%v", res.Case.Name, res.Missed, res.FalsePositive)
		}
	}
}
