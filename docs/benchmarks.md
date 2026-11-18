# Benchmarks

> **CAVEAT — READ FIRST: the numbers below are VM-local, measured on a small
> shared virtual machine (1.5 shared CPUs). They are NOT server numbers and
> must NOT be quoted as SonuShield's capacity.** Real capacity must be
> measured on your own server with its real CPU, network, and backend, using
> the instructions at the bottom of this page. The useful takeaway from the
> VM run is the *relative* cost of each code path on identical hardware, not
> any absolute figure.

## VM-local results — 18 November 2026

### Conditions

- **Hardware:** shared Linux VM, 1.5 shared CPUs, ~6 GB shared RAM. Other
  tenants' load affects results (visible as p99 jitter — see Notes).
- **Proxy:** built from commit `bc2588c`, default config except raised rate
  limits so the bench itself never trips them. TLS on :443 with a throwaway
  self-signed certificate.
- **Backend:** minimal Go HTTP server on `127.0.0.1:18081` answering `GET /`
  with an 11-byte body. (An earlier run against a Python backend measured
  the backend, not the proxy — 242 rps — and was discarded.)
- **Load generator:** `tools/bench/` (Go, standard library only). 32
  concurrent workers, HTTP/2 over TLS with SNI `example.com`, keep-alive,
  30 s per scenario (15 s baseline), localhost only.
- **Scenarios:**
  1. **Passthrough** — valid Stage-1 cookie warmed once per worker, then
     `GET /` proxied to the backend.
  2. **Stage-1 challenge flow** — fresh cookie jar per iteration: `GET /` →
     302 + cookie → follow → 200. One counted request = one full 2-request
     flow, so the HTTP request rate is ~2× the flow rate.
  3. **Stage-2 PoW page** — stage locked at 2 via the control API, requests
     without a cookie served the PoW HTML page. No solving (solving happens
     in the visitor's browser, not on the proxy).

### Results

| Scenario | req/s | mean | p50 | p95 | p99 | errors |
|---|---|---|---|---|---|---|
| Baseline: direct to backend (no proxy) | 17,737 | 1.8 ms | 0.6 ms | 2.9 ms | 56 ms | 0/266,050 |
| 1. Passthrough + valid cookie | 3,437 | 9.3 ms | 4.1 ms | 58 ms | 64 ms | 0/103,104 |
| 2. Stage-1 challenge flow (flows/s) | 1,633 | 19.6 ms | 8.3 ms | 73 ms | 86 ms | 0/48,980 |
| 3. Stage-2 PoW page serving | 7,505 | 4.3 ms | 1.3 ms | 10 ms | 63 ms | 0/225,161 |

### Reading the numbers honestly

- **Proxy overhead on this VM is large.** Passthrough runs at ~19% of the
  direct-backend rate (3,437 vs 17,737 rps). That reflects TLS termination +
  fingerprinting + rule evaluation + reverse-proxying on 1.5 shared cores.
  The ratio — not the absolute rps — is the portable observation, and even
  the ratio will shift on real hardware with more cores and a real network.
- **The challenge flow costs ~2× a passthrough** per visitor (1,633 flows/s ≈
  3,265 HTTP req/s), as expected: two requests, a cookie HMAC, and a redirect.
- **PoW page serving is cheap** (7,505 rps): static page, no backend
  round-trip. Under attack, Stage 2 sheds backend load effectively on this
  hardware.
- **p99 is VM jitter, not proxy behaviour.** The direct-to-backend baseline
  also shows p99 ≈ 56 ms with p50 ≈ 0.6 ms — shared-CPU scheduling stalls.
  Judge by p50/p95 here; p99 needs a quiet machine to mean anything.
- **Zero errors in all scenarios.** No 5xx, no timeouts, no dropped
  connections at these rates on this VM.
- **What was NOT measured:** Stage-3 captcha serving, solving cost
  (browser-side), behaviour under real attack traffic mixes, multi-domain
  configs, cache on/off deltas, memory/CPU profiles, or anything over a real
  network. A server-side load test on your hardware is still required before
  any capacity claim.

## Running the benchmark on a real server

Run the load generator from a **separate machine** on the same network as the
proxy (or at least a separate process you can account for): generating load
on the same cores as the proxy measures the generator, not the proxy. Never
run it against a production domain — use a throwaway domain and backend.

### 1. Build the proxy and the bench tool

```sh
git clone https://github.com/sonudigitalmindset-design/SonuShield.git
cd SonuShield
go build -o /tmp/ssbench/sonushield .
cd tools/bench && go build -o /tmp/ssbench/bench . && cd ../..
```

`tools/bench` is its own tiny Go module (standard library only); it builds
standalone and is not part of `go build ./...` from the repo root.

### 2. Stand up a throwaway proxy + backend

Create a scratch directory with a throwaway `config.json` (one domain, a
self-signed certificate for it, rate limits raised high enough that the bench
never trips them) and a minimal backend that answers `GET /` with a small
fixed body. The backend must be fast enough not to be the bottleneck —
verify that first with the baseline run in step 4. Start the proxy from the
scratch directory (it reads `config.json` from its working directory), with
stdin kept open (a pipe from `sleep` works) so the terminal command reader
does not spin.

### 3. Baseline first

Point the bench tool at the backend directly (same workers, same duration)
to establish what the backend alone can do. If the proxy numbers later land
near the baseline, you are measuring the backend, not the proxy — fix the
backend before drawing conclusions.

### 4. Run the three scenarios

```sh
# Passthrough: valid cookie warmed once per worker.
/tmp/ssbench/bench -mode cookie -duration 30s -workers 32 \
  -url https://<proxy-ip>:443/ -host bench.example.com

# Stage-1 challenge flow: fresh visitor on every iteration.
/tmp/ssbench/bench -mode challenge -duration 30s -workers 32 \
  -url https://<proxy-ip>:443/ -host bench.example.com

# Stage-2 PoW page: lock stage 2 via the control API first
# (SET_STAGE with stage=2; stage=0 unlocks back to automatic),
# then run with no cookie.
/tmp/ssbench/bench -mode pow -duration 30s -workers 32 \
  -url https://<proxy-ip>:443/ -host bench.example.com
```

The `-host` value is both the `Host` header and the TLS SNI name: it must be
a domain the proxy serves, or the handshake fails. The tool skips certificate
verification (`InsecureSkipVerify`) because bench certificates are
self-signed — it is a test-only tool; never point it at a production host
and treat its results as a security assessment.

### 5. Record the conditions with the numbers

A benchmark number without its conditions is marketing. Record: CPU model
and count, RAM, network path (localhost / LAN / internet), proxy commit,
config differences from default, backend implementation, workers, duration,
and the full output line (requests, errors, mean/p50/p95/p99). Run each
scenario at least twice and report the range, not the best run.
