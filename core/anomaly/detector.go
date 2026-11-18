// Package anomaly implements the experimental log-only
// anomaly signal (Batch 3, item 4).
//
// The detector aggregates requests into (domain, IP,
// 10-second window) samples and scores each sample with a
// weighted z-score over seven signals already computed by
// the proxy: request count, distinct paths, distinct
// user-agents, distinct TLS fingerprints, mean risk score,
// share of cookie-less (challenged-path) requests, and the
// sample's dominant fingerprint's share of all window
// entries. The reference means, standard deviations, and
// threshold are fixed constants taken from the offline
// evaluation in docs/ml-evaluation.md — they describe the
// synthetic harness traffic the evaluation ran on, not
// real visitor traffic, and the detector is expected to be
// miscalibrated on real traffic. It is OFF by default
// (proxy.anomalyDetection), it NEVER changes suspicion
// levels, challenges, or blocks, and it only emits
// "anomaly" log entries for the operator to review. There
// is no training, no model file, and no visitor data
// leaves the proxy; nothing here is "AI protection" and
// user-facing text must never call it that.
//
// Scoring runs when a window completes: either lazily, on
// the first observation of the next window, or from the
// one-second monitor tick. Two deliberate deviations from
// the evaluated candidate, both documented in
// docs/ml-evaluation.md: windows with fewer than 10 total
// entries are not scored (fingerprint share is meaningless
// in sparse windows — a lone request would otherwise flag
// itself), and at most 100 anomalies are reported per
// (domain, window) to bound log volume during a real
// attack.
//
// State is bounded: only the current window per domain is
// kept, at most 10,000 IPs per window, and per-sample sets
// are capped. When disabled, Observe is a no-op and no
// state is accumulated.
package anomaly

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// WindowSeconds matches the evaluation's aggregation
// window: samples are (IP, 10-second window) aggregates
// aligned to Unix-epoch 10s boundaries.
const WindowSeconds = 10

// featureRef is one feature's reference distribution from
// the evaluation's TRAIN NORMAL samples, plus its anomaly
// direction: +1 means higher values are more suspicious,
// -1 means lower values are more suspicious.
type featureRef struct {
	mean, std float64
	dir       float64
}

// Reference statistics and threshold from the final
// Batch 3 evaluation run (docs/ml-evaluation.md): means
// and standard deviations of the TRAIN NORMAL samples
// (37 samples), threshold tuned on the train split for
// max F1. An earlier run agreed on the verdict with
// slightly different values; the threshold is sensitive
// to the small sample size, which is one more reason the
// detector is experimental and log-only.
var reference = []featureRef{
	{mean: 4.622, std: 0.748, dir: +1},  // count
	{mean: 4.622, std: 0.748, dir: -1},  // distinct_paths
	{mean: 1.000, std: 1.000, dir: -1},  // distinct_uas
	{mean: 1.000, std: 1.000, dir: -1},  // distinct_fps
	{mean: 37.865, std: 7.072, dir: +1}, // mean_risk
	{mean: 1.000, std: 1.000, dir: +1},  // challenged_share
	{mean: 0.557, std: 0.151, dir: +1},  // fp_share
}

// threshold is the score above which a sample is reported.
// Tuned on the evaluation's train split for max F1.
const threshold = 3.221

const (
	// maxIPsPerWindow bounds memory per (domain, window).
	// Past the cap, new IPs are not tracked.
	maxIPsPerWindow = 10000
	// Per-sample set caps. Past the cap, new values are
	// ignored (the distinct count saturates).
	maxPathsPerSample = 64
	maxUAsPerSample   = 16
	maxFPsPerSample   = 16
	// maxFPsPerWindow bounds the window-global fingerprint
	// histogram. Past the cap, new fingerprints are not
	// counted toward fingerprint share.
	maxFPsPerWindow = 4096
	// minWindowTotal is the sparse-window guard: windows
	// with fewer entries are not scored.
	minWindowTotal = 10
	// maxAnomaliesPerWindow bounds log volume per
	// (domain, window); the highest scores win.
	maxAnomaliesPerWindow = 100
)

// Anomaly is one scored sample that exceeded the
// threshold. It is a log-only signal: nothing in the proxy
// acts on it.
type Anomaly struct {
	Domain          string
	IP              string
	WindowStart     int64
	Score           float64
	Count           int
	DistinctPaths   int
	DistinctUAs     int
	DistinctFPs     int
	MeanRisk        float64
	ChallengedShare float64
	FPShare         float64
}

// sample accumulates one (IP, window) aggregate.
type sample struct {
	count      int
	paths      map[string]struct{}
	uas        map[string]struct{}
	fps        map[string]struct{}
	riskSum    int
	challenged int
	fpCounts   map[string]int
}

func newSample() *sample {
	return &sample{
		paths:    make(map[string]struct{}),
		uas:      make(map[string]struct{}),
		fps:      make(map[string]struct{}),
		fpCounts: make(map[string]int),
	}
}

// windowState is one domain's current aggregation window.
type windowState struct {
	start    int64
	total    int
	perIP    map[string]*sample
	fpCounts map[string]int
}

func newWindowState(start int64) *windowState {
	return &windowState{
		start:    start,
		perIP:    make(map[string]*sample),
		fpCounts: make(map[string]int),
	}
}

// Detector aggregates observations and scores completed
// windows. The zero value is not usable; use New.
type Detector struct {
	mu      sync.Mutex
	enabled atomic.Bool
	windows map[string]*windowState
	now     func() time.Time
}

// New returns a disabled detector.
func New() *Detector {
	return &Detector{
		windows: make(map[string]*windowState),
		now:     time.Now,
	}
}

// SetEnabled turns the detector on or off. Toggling
// either way discards accumulated state, so enabling
// always starts from a fresh window.
func (d *Detector) SetEnabled(v bool) {
	d.mu.Lock()
	d.windows = make(map[string]*windowState)
	d.mu.Unlock()
	d.enabled.Store(v)
}

// Enabled reports whether the detector is on.
func (d *Detector) Enabled() bool {
	return d.enabled.Load()
}

// Observe records one evaluated request. challenged
// reports whether the request arrived without a challenge
// cookie (the challenged-path share feature). When the
// observation falls in a new window, the completed window
// is scored and its anomalies returned; otherwise the
// return is nil. When disabled, Observe is a no-op.
func (d *Detector) Observe(domain, ip, path, ua, fp string, risk int, challenged bool) []Anomaly {
	if !d.enabled.Load() {
		return nil
	}
	now := d.now().Unix()
	start := now - now%WindowSeconds
	d.mu.Lock()
	defer d.mu.Unlock()
	w, ok := d.windows[domain]
	if !ok {
		w = newWindowState(start)
		d.windows[domain] = w
	}
	var done []Anomaly
	if w.start != start {
		done = scoreWindow(domain, w)
		w = newWindowState(start)
		d.windows[domain] = w
	}
	w.total++
	s, ok := w.perIP[ip]
	if !ok {
		if len(w.perIP) >= maxIPsPerWindow {
			// Over the cap: count toward the window
			// total (fingerprint share stays honest)
			// but track no per-IP sample.
			d.countFP(w, fp)
			return done
		}
		s = newSample()
		w.perIP[ip] = s
	}
	s.count++
	if len(s.paths) < maxPathsPerSample {
		s.paths[path] = struct{}{}
	}
	if len(s.uas) < maxUAsPerSample {
		s.uas[ua] = struct{}{}
	}
	if len(s.fps) < maxFPsPerSample {
		s.fps[fp] = struct{}{}
	}
	s.riskSum += risk
	if challenged {
		s.challenged++
	}
	if _, ok := s.fpCounts[fp]; !ok && len(s.fpCounts) >= maxFPsPerSample {
		// Saturate like the fps set.
	} else {
		s.fpCounts[fp]++
	}
	d.countFP(w, fp)
	return done
}

// countFP records one fingerprint occurrence in the
// window-global histogram. Call with d.mu held.
func (d *Detector) countFP(w *windowState, fp string) {
	if _, ok := w.fpCounts[fp]; !ok && len(w.fpCounts) >= maxFPsPerWindow {
		return
	}
	w.fpCounts[fp]++
}

// Tick scores every window that has completed by now and
// rotates it out, returning the anomalies found. It lets
// quiet periods (no new observations) still close windows.
// When disabled, Tick is a no-op.
func (d *Detector) Tick() []Anomaly {
	if !d.enabled.Load() {
		return nil
	}
	now := d.now().Unix()
	start := now - now%WindowSeconds
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Anomaly
	for domain, w := range d.windows {
		if w.start != start {
			out = append(out, scoreWindow(domain, w)...)
			d.windows[domain] = newWindowState(start)
		}
	}
	return out
}

// scoreWindow scores every sample in a completed window.
// Windows below the sparse guard are not scored. Call with
// d.mu held (it only reads the window).
func scoreWindow(domain string, w *windowState) []Anomaly {
	if w.total < minWindowTotal {
		return nil
	}
	var out []Anomaly
	for ip, s := range w.perIP {
		// Dominant fingerprint: the sample's most
		// frequent fingerprint; its share is computed
		// over ALL window entries, as in the evaluation.
		dominant := ""
		dominantCount := 0
		for fp, n := range s.fpCounts {
			if n > dominantCount {
				dominant, dominantCount = fp, n
			}
		}
		fpShare := 0.0
		if w.total > 0 {
			fpShare = float64(w.fpCounts[dominant]) / float64(w.total)
		}
		meanRisk := 0.0
		if s.count > 0 {
			meanRisk = float64(s.riskSum) / float64(s.count)
		}
		challengedShare := 0.0
		if s.count > 0 {
			challengedShare = float64(s.challenged) / float64(s.count)
		}
		a := Anomaly{
			Domain:          domain,
			IP:              ip,
			WindowStart:     w.start,
			Count:           s.count,
			DistinctPaths:   len(s.paths),
			DistinctUAs:     len(s.uas),
			DistinctFPs:     len(s.fps),
			MeanRisk:        meanRisk,
			ChallengedShare: challengedShare,
			FPShare:         fpShare,
		}
		a.Score = scoreSample(a)
		if a.Score > threshold {
			out = append(out, a)
		}
	}
	// Highest scores first; cap the report volume.
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > maxAnomaliesPerWindow {
		out = out[:maxAnomaliesPerWindow]
	}
	return out
}

// scoreSample is the evaluated candidate, verbatim: the
// sum of per-feature z-scores (standardized on the TRAIN
// NORMAL reference, clipped to ±3), each multiplied by its
// anomaly direction.
func scoreSample(a Anomaly) float64 {
	features := []float64{
		float64(a.Count),
		float64(a.DistinctPaths),
		float64(a.DistinctUAs),
		float64(a.DistinctFPs),
		a.MeanRisk,
		a.ChallengedShare,
		a.FPShare,
	}
	score := 0.0
	for i, x := range features {
		ref := reference[i]
		z := (x - ref.mean) / ref.std
		if z > 3 {
			z = 3
		} else if z < -3 {
			z = -3
		}
		score += z * ref.dir
	}
	return score
}
