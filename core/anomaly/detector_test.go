package anomaly

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// fixedClock lets tests step time across window
// boundaries deterministically.
type fixedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestDetector(start time.Time) (*Detector, *fixedClock) {
	clock := &fixedClock{now: start}
	d := New()
	d.now = clock.Now
	d.SetEnabled(true)
	return d, clock
}

// windowStart returns a Unix time aligned to a 10s
// boundary for deterministic tests.
func windowStart() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}

func TestScoreSampleAttackAboveNormalBelow(t *testing.T) {
	attack := Anomaly{
		Count: 100, DistinctPaths: 1, DistinctUAs: 1,
		DistinctFPs: 1, MeanRisk: 60,
		ChallengedShare: 1.0, FPShare: 0.9,
	}
	if got := scoreSample(attack); got <= threshold {
		t.Fatalf("attack-like score = %v, want > %v", got, threshold)
	}
	normal := Anomaly{
		Count: 5, DistinctPaths: 5, DistinctUAs: 1,
		DistinctFPs: 1, MeanRisk: 37,
		ChallengedShare: 1.0, FPShare: 0.2,
	}
	if got := scoreSample(normal); got > threshold {
		t.Fatalf("normal-like score = %v, want <= %v", got, threshold)
	}
	// Deterministic: same sample, same score.
	if a, b := scoreSample(attack), scoreSample(attack); a != b {
		t.Fatalf("non-deterministic scores: %v vs %v", a, b)
	}
}

func TestConstantsMatchEvaluation(t *testing.T) {
	// These values are copied from the final evaluation
	// run's output (docs/ml-evaluation.md). If the
	// evaluation is re-run, update the code and the docs
	// together; this test pins them to each other.
	if threshold != 3.221 {
		t.Fatalf("threshold = %v, want 3.221", threshold)
	}
	if len(reference) != 7 {
		t.Fatalf("reference has %d features, want 7", len(reference))
	}
	want := []featureRef{
		{mean: 4.622, std: 0.748, dir: +1},
		{mean: 4.622, std: 0.748, dir: -1},
		{mean: 1.000, std: 1.000, dir: -1},
		{mean: 1.000, std: 1.000, dir: -1},
		{mean: 37.865, std: 7.072, dir: +1},
		{mean: 1.000, std: 1.000, dir: +1},
		{mean: 0.557, std: 0.151, dir: +1},
	}
	for i, w := range want {
		if reference[i] != w {
			t.Fatalf("reference[%d] = %+v, want %+v", i, reference[i], w)
		}
	}
}

func TestObserveRotationScoresCompletedWindow(t *testing.T) {
	d, clock := newTestDetector(windowStart())
	// Flood-like IP: 50 requests, one path/UA/fingerprint.
	for i := 0; i < 50; i++ {
		if out := d.Observe("example.com", "10.0.0.1", "/login", "bot/1", "fp-flood", 60, true); len(out) != 0 {
			t.Fatalf("Observe mid-window returned anomalies: %+v", out)
		}
	}
	// Normal IPs: varied paths, shared window total.
	for i := 0; i < 10; i++ {
		d.Observe("example.com", fmt.Sprintf("10.0.0.%d", 2+i), fmt.Sprintf("/page%d", i), "Mozilla/5.0", fmt.Sprintf("fp-%d", i), 30, false)
	}
	// Cross into the next window: rotation scores the old one.
	clock.Advance(11 * time.Second)
	out := d.Observe("example.com", "10.0.0.1", "/login", "bot/1", "fp-flood", 60, true)
	if len(out) != 1 {
		t.Fatalf("rotation returned %d anomalies, want 1: %+v", len(out), out)
	}
	a := out[0]
	if a.IP != "10.0.0.1" || a.Domain != "example.com" {
		t.Fatalf("anomaly = %+v, want the flood IP", a)
	}
	if a.Count != 50 || a.DistinctPaths != 1 || a.DistinctFPs != 1 {
		t.Fatalf("anomaly features wrong: %+v", a)
	}
	if a.Score <= threshold {
		t.Fatalf("anomaly score = %v, want > %v", a.Score, threshold)
	}
	if a.WindowStart != windowStart().Unix() {
		t.Fatalf("window start = %d, want %d", a.WindowStart, windowStart().Unix())
	}
}

func TestTickScoresQuietWindows(t *testing.T) {
	d, clock := newTestDetector(windowStart())
	for i := 0; i < 50; i++ {
		d.Observe("example.com", "10.0.0.9", "/x", "bot/1", "fp-flood", 60, true)
	}
	for i := 0; i < 10; i++ {
		d.Observe("example.com", fmt.Sprintf("10.0.1.%d", i), "/p", "Mozilla/5.0", "fp-n", 30, false)
	}
	clock.Advance(12 * time.Second)
	out := d.Tick()
	if len(out) != 1 || out[0].IP != "10.0.0.9" {
		t.Fatalf("Tick returned %+v, want the flood anomaly", out)
	}
	// Second tick in the same window: nothing new.
	if out := d.Tick(); len(out) != 0 {
		t.Fatalf("second Tick returned %+v, want none", out)
	}
}

func TestSparseWindowGuard(t *testing.T) {
	d, clock := newTestDetector(windowStart())
	// A lone extreme request in a 3-entry window must NOT
	// flag: fingerprint share is meaningless when sparse.
	d.Observe("example.com", "10.0.0.1", "/x", "bot/1", "fp-only", 90, true)
	d.Observe("example.com", "10.0.0.2", "/x", "bot/1", "fp-only", 90, true)
	d.Observe("example.com", "10.0.0.3", "/x", "bot/1", "fp-only", 90, true)
	clock.Advance(11 * time.Second)
	if out := d.Tick(); len(out) != 0 {
		t.Fatalf("sparse window scored: %+v", out)
	}
}

func TestDisabledIsNoop(t *testing.T) {
	d := New()
	if d.Enabled() {
		t.Fatal("new detector must start disabled")
	}
	for i := 0; i < 50; i++ {
		d.Observe("example.com", "10.0.0.1", "/x", "bot/1", "fp", 90, true)
	}
	if out := d.Tick(); len(out) != 0 {
		t.Fatalf("disabled detector returned %+v", out)
	}
	d.mu.Lock()
	n := len(d.windows)
	d.mu.Unlock()
	if n != 0 {
		t.Fatalf("disabled detector accumulated %d windows", n)
	}
}

func TestFPShareUsesWindowGlobalCounts(t *testing.T) {
	d, clock := newTestDetector(windowStart())
	// Two IPs share one fingerprint; together they are
	// half the window, so each sample's fpShare is 0.5.
	for i := 0; i < 25; i++ {
		d.Observe("example.com", "10.0.0.1", "/a", "u", "fp-shared", 50, true)
		d.Observe("example.com", "10.0.0.2", "/a", "u", "fp-shared", 50, true)
	}
	for i := 0; i < 50; i++ {
		d.Observe("example.com", "10.0.0.3", "/b", "u2", "fp-other", 20, false)
	}
	clock.Advance(11 * time.Second)
	out := d.Tick()
	byIP := map[string]Anomaly{}
	for _, a := range out {
		byIP[a.IP] = a
	}
	a, ok := byIP["10.0.0.1"]
	if !ok {
		t.Fatalf("no anomaly for 10.0.0.1 in %+v", out)
	}
	if a.FPShare != 0.5 {
		t.Fatalf("fpShare = %v, want 0.5 (window-global)", a.FPShare)
	}
}

func TestIPCapBoundsState(t *testing.T) {
	d, _ := newTestDetector(windowStart())
	for i := 0; i < maxIPsPerWindow+500; i++ {
		d.Observe("example.com", fmt.Sprintf("10.1.%d.%d", i/256, i%256), "/x", "u", "fp", 10, false)
	}
	d.mu.Lock()
	n := len(d.windows["example.com"].perIP)
	total := d.windows["example.com"].total
	d.mu.Unlock()
	if n != maxIPsPerWindow {
		t.Fatalf("tracked IPs = %d, want cap %d", n, maxIPsPerWindow)
	}
	if total != maxIPsPerWindow+500 {
		t.Fatalf("window total = %d, want %d", total, maxIPsPerWindow+500)
	}
}

func TestConcurrentObserve(t *testing.T) {
	d, _ := newTestDetector(windowStart())
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				d.Observe("example.com", fmt.Sprintf("10.0.0.%d", g), "/p", "u", "fp", 10, false)
			}
		}(g)
	}
	wg.Wait()
	if out := d.Tick(); len(out) != 0 {
		// Same window: Tick must not score prematurely.
		t.Fatalf("Tick scored the current window: %+v", out)
	}
}
