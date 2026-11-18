# ML Anomaly Evaluation

An offline evaluation of a lightweight anomaly detector
over signals the proxy already computes — and the
experimental log-only detector that was shipped because
the evaluation passed a rule fixed *before* the numbers
were seen. This page reports what was measured, on what
data, and what the shipped code is and is not. Nothing
here is "AI protection", and no user-facing text may call
it that.

## The pre-registered ship rule

Fixed before any evaluation ran:

> Ship a log-only detector **only if** the candidate's F1
> beats the count-threshold baseline's F1 on the held-out
> test split by **at least 0.10**, **and** the candidate's
> test precision is **at least 0.70**. Otherwise document
> the evaluation honestly and ship nothing.

All three runs below passed the rule, so the detector shipped
— log-only, off by default, with a clear disable. See
[The shipped detector](#the-shipped-detector).

## Method

**Data generation.** The Batch 3 smoke harness
(`~/workspace/sonushield-smoke-batch3/`, kept outside
this repo) drove the real proxy binary with scripted
traffic in five 30-second phases aligned to 10-second
window boundaries, and recorded a label file of
`startUnix,endUnix,attack` per phase:

| Phase | Traffic | Label |
|-------|---------|-------|
| normal-1 | 6 scripted users | normal |
| flood | 6 users + 2 flood bots (10 req/s each) | attack |
| normal-2 | 6 scripted users | normal |
| distributed | 6 users + 12 slow bots (0.5 req/s each, shared UA/path/TLS) | attack |
| normal-3 | 6 scripted users | normal |

The scripted users varied paths (6), user-agents (6),
source IPs, and TLS profiles (3, to vary ClientHello
fingerprints). Every request used a fresh cookie jar, so
every request logged one challenge entry. Phases were
interleaved so both classes appear in both the train and
test splits. A few requests (at most ~0.3s of traffic per
boundary) spilled across phase boundaries into the next
phase's first window; that label noise slightly hurts
both detectors and is disclosed, not hidden.

**Samples.** The evaluator (`tools/ml-eval/`, a
standalone stdlib-only Go module) reads the proxy's JSON
log plus the label file and aggregates (IP, 10-second
window) samples. Windows with no label, or straddling a
label boundary, are dropped.

**Features** (per sample):

| Feature | Direction | Meaning |
|---------|-----------|---------|
| `count` | higher = suspicious | requests in the window |
| `distinct_paths` | lower = suspicious | distinct paths |
| `distinct_uas` | lower = suspicious | distinct user-agents |
| `distinct_fps` | lower = suspicious | distinct TLS fingerprints |
| `mean_risk` | higher = suspicious | mean risk score (0–100) |
| `challenge_share` | higher = suspicious | share of challenge/block log entries |
| `fp_share` | higher = suspicious | the sample's dominant fingerprint's share of *all* window entries |

**Split.** Time-based 70/30 train/test split (earlier
windows train, later windows test), so the test measures
forward generalization, not memorization.

**Detectors.**

- *Baseline:* a count threshold, tuned on the train
  split for maximum F1 — the existing threshold-rule
  approach, fairly tuned.
- *Candidate:* a weighted z-score. Each feature is
  standardized using the TRAIN NORMAL samples' mean and
  standard deviation only (never test data), clipped to
  ±3, multiplied by its anomaly direction, and summed.
  The score threshold is tuned on the train split for
  maximum F1. No learned weights, no model file, no
  training on visitor data.

## Results

### Run 2 (final — shipped constants)

133 samples: train 93 (56 attack, 37 normal), test 40
(22 attack, 18 normal).

| Detector | Threshold | TP | FP | TN | FN | Precision | Recall | F1 | Train F1 |
|----------|-----------|----|----|----|----|-----------|--------|----|----------|
| Baseline | count > 1 | 22 | 18 | 0 | 0 | 0.550 | 1.000 | 0.710 | 0.757 |
| Candidate | z > 3.221 | 16 | 0 | 18 | 6 | 1.000 | 0.727 | 0.842 | 0.902 |

Verdict: **CANDIDATE_WINS — F1 +0.132, precision 1.000.**
The rule required +0.10 and precision ≥ 0.70: both met.
Note the baseline tuned to the degenerate threshold
`count > 1` (flag everything): on this data no count
threshold separates the classes, because the distributed
bots are individually slow.

Reference statistics (train normal, 37 samples) — these
are the constants baked into the shipped detector:

| Feature | Mean | Std | Direction |
|---------|------|-----|-----------|
| count | 4.622 | 0.748 | +1 |
| distinct_paths | 4.622 | 0.748 | −1 |
| distinct_uas | 1.000 | 1.000 | −1 |
| distinct_fps | 1.000 | 1.000 | −1 |
| mean_risk | 37.865 | 7.072 | +1 |
| challenge_share | 1.000 | 1.000 | +1 |
| fp_share | 0.557 | 0.151 | +1 |

(Zero-variance features get std floored to 1.0 by the
evaluator, so they contribute ~0 — `distinct_uas`,
`distinct_fps`, and `challenge_share` carried no signal
in this data, because every scripted user had one UA, one
fingerprint, and every request was challenged.)

### Run 1 (confirmation)

133 samples: train 93 (57 attack, 36 normal), test 40
(21 attack, 19 normal).

| Detector | Threshold | TP | FP | TN | FN | Precision | Recall | F1 | Train F1 |
|----------|-----------|----|----|----|----|-----------|--------|----|----------|
| Baseline | count > 4 | 15 | 12 | 7 | 6 | 0.556 | 0.714 | 0.625 | 0.744 |
| Candidate | z > 1.968 | 19 | 5 | 14 | 2 | 0.792 | 0.905 | 0.844 | 0.904 |

Verdict: **CANDIDATE_WINS — F1 +0.219, precision 0.792.**

### Run 3 (second confirmation)

134 samples: train 93 (56 attack, 37 normal), test 41
(22 attack, 19 normal). Baseline (count > 1): F1 0.710,
precision 0.550, recall 1.000. Candidate (z > 1.838):
TP=20, FP=0, TN=19, FN=2, precision 1.000, recall 0.909,
F1 0.952. Verdict: **CANDIDATE_WINS — F1 +0.243,
precision 1.000.**

### Reading the three runs together

- The candidate's test F1 was high in all runs (0.844,
  0.842, 0.952); the baseline's stayed low (0.625,
  0.710, 0.710). The margin cleared +0.10 in all three
  runs, and candidate precision was ≥ 0.79 in all three.
- The tuned threshold moved a lot across runs (1.968,
  3.221, 1.838) on 93 train samples. Thresholds tuned
  on this little data are unstable — one more reason
  the shipped detector is experimental and log-only.
- The distributed phase is what the baseline cannot
  catch: 12 bots at 0.5 req/s each look individually
  normal by count, but share one fingerprint, one UA,
  and one path — the multivariate candidate sees the
  shared fingerprint (`fp_share`) and the missing
  diversity.

## The shipped detector

`core/anomaly`, wired into the proxy behind
`proxy.anomalyDetection` (**off by default**):

- Aggregates requests into (domain, IP, 10-second
  window) samples using the same seven features and the
  run-2 reference constants and threshold above,
  verbatim. The live `challenged_share` is the share of
  requests that arrived *without* a challenge cookie,
  matching the evaluation's semantics (every evaluated
  request there was cookie-less).
- Scores a window when it completes — lazily on the
  first observation of the next window, or from the
  one-second monitor tick — and emits one structured-log
  entry per flagged sample: `Event: "anomaly"`,
  `Action: "anomaly_signal"`, score in `anomaly_score`.
- **Never** changes suspicion levels, challenges,
  blocks, or any other enforcement. There is no
  enforcement mode. Observation covers requests that
  reach firewall-rule evaluation; early-blocked requests
  (rate limits, blocklists) are not observed.
- Two deliberate deviations from the evaluated
  candidate, both disclosed here: windows with fewer
  than 10 total entries are not scored (fingerprint
  share is meaningless in sparse windows — a lone
  request would otherwise flag itself), and at most 100
  anomalies are reported per (domain, window) to bound
  log volume during a real attack.
- Bounded state: only the current window per domain,
  at most 10,000 IPs per window, capped per-sample sets.
  When disabled, observation is a no-op and no state is
  kept. Toggling the flag (at startup or via reload)
  discards accumulated state.
- `GET_PROXY_FEATURES` reports `ANOMALY_DETECTION`
  read-only. Enabling is config-file-only.

Enable:

```json
"proxy": { "anomalyDetection": true }
```

then reload. Disable by setting it `false` (or removing
it) and reloading. Review flagged IPs in the structured
log (`logFormat: "json"`) or via log search; treat every
flag as a lead to investigate, never as proof of an
attack.

## Honesty limits — read before trusting it

- **Synthetic data only.** Six scripted users and
  fourteen scripted bots, 150 seconds, 133 samples. The
  numbers describe this setup, not real visitor
  traffic. Real traffic has different rates, paths,
  fingerprints, and risk-score distributions, so the
  baked-in constants are **expected to be miscalibrated**
  on a real site. False positives and missed attacks
  should both be expected until the detector is
  re-evaluated on real (labelled, consented) data.
- **Small samples.** 93 train / 40 test samples. The
  threshold instability across runs (1.968 vs 3.221)
  shows how little this data pins down.
- **Fresh-jar artifact.** Every harness request was
  cookie-less and challenged, so `challenge_share` was
  constant 1.0 and carried no signal. On real traffic
  it varies, and its reference (mean 1.0, std 1.0) can
  only lower scores — conservative, but unvalidated.
- **No per-site calibration.** The constants are fixed
  at build time. There is no online learning, no
  per-domain baseline, and no feedback loop.
- **What was verified live.** The Batch 3 harness
  (Phase E) proves the wiring end to end: with the flag
  on, flood IPs are flagged in the live log with scores
  above the threshold and flood IPs are the majority of
  flagged entries; with the flag off, the log contains
  zero anomaly entries. The detector package has unit
  tests (including a test pinning the constants to this
  page) and is race-clean. None of that proves accuracy
  on real traffic.

## Re-running the evaluation

1. Run the Batch 3 smoke harness
   (`~/workspace/sonushield-smoke-batch3/smoke.py`);
   Phase D regenerates the dataset, labels, and
   evaluation output (`ml-dataset.jsonl`,
   `ml-labels.txt`, `ml-eval-output.txt` in the harness
   directory).
2. Or run the evaluator directly against any proxy JSON
   log plus a label file (it is a standalone module, so
   run it from its own directory):
   `cd tools/ml-eval && go run . -log <log.jsonl> -labels <labels.txt>`
   Label lines are `startUnix,endUnix,attack` (`attack`
   is 0 or 1).
3. If you re-run with different traffic and the numbers
   change, update `core/anomaly/detector.go` and this
   page together; `TestConstantsMatchEvaluation` fails
   until they agree.
