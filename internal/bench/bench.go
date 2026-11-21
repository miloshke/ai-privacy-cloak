package bench

import (
	"fmt"
	"io"
	"sort"
	"time"

	"cloak/internal/detect"
)

type CaseResult struct {
	Case          Case
	Found         []detect.Kind
	Missed        []detect.Kind
	FalsePositive []detect.Kind // anything found on an ExpectClean case
	LatencyP50    time.Duration
	LatencyP95    time.Duration
}

func (r CaseResult) Passed() bool {
	if r.Case.ExpectClean {
		return len(r.FalsePositive) == 0
	}
	return len(r.Missed) == 0
}

type Report struct {
	Results []CaseResult
}

func (r Report) PassedCount() int {
	n := 0
	for _, res := range r.Results {
		if res.Passed() {
			n++
		}
	}
	return n
}

// Run scans every case with d, re-running each scan `iterations` times to
// get a stable latency distribution (a single call is too noisy to report).
func Run(d *detect.Detector, cases []Case, iterations int) Report {
	var report Report
	for _, c := range cases {
		report.Results = append(report.Results, runCase(d, c, iterations))
	}
	return report
}

func runCase(d *detect.Detector, c Case, iterations int) CaseResult {
	matches := d.Scan(c.Text)
	foundSet := map[detect.Kind]bool{}
	for _, m := range matches {
		foundSet[m.Kind] = true
	}

	res := CaseResult{Case: c}

	if c.ExpectClean {
		for k := range foundSet {
			res.FalsePositive = append(res.FalsePositive, k)
		}
	} else {
		wantSet := map[detect.Kind]bool{}
		for _, k := range c.WantKinds {
			wantSet[k] = true
			if foundSet[k] {
				res.Found = append(res.Found, k)
			} else {
				res.Missed = append(res.Missed, k)
			}
		}
	}

	durations := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		d.Scan(c.Text)
		durations[i] = time.Since(start)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	res.LatencyP50 = percentile(durations, 0.50)
	res.LatencyP95 = percentile(durations, 0.95)

	return res
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)-1))
	return sorted[idx]
}

func (r Report) Print(w io.Writer) {
	fmt.Fprintf(w, "cloak leak-corpus benchmark - %d cases\n\n", len(r.Results))
	for _, res := range r.Results {
		status := "PASS"
		if !res.Passed() {
			status = "FAIL"
		}
		fmt.Fprintf(w, "[%s] %-32s p50=%-10s p95=%-10s\n", status, res.Case.Name, res.LatencyP50, res.LatencyP95)
		fmt.Fprintf(w, "      %s\n", res.Case.Description)
		if len(res.Missed) > 0 {
			fmt.Fprintf(w, "      missed: %v\n", res.Missed)
		}
		if len(res.FalsePositive) > 0 {
			fmt.Fprintf(w, "      false positive: %v\n", res.FalsePositive)
		}
	}
	fmt.Fprintf(w, "\n%d/%d cases passed\n", r.PassedCount(), len(r.Results))
}
