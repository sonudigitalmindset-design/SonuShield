package firewall

// Composite risk score (Batch 5).
//
// ComputeRiskScore combines the signals available when a request is
// evaluated into one 0-100 score. It is a heuristic for ranking and
// clustering, NOT a verdict: a high score never proves a request is
// malicious, and a low score never proves it is safe. Rules match on
// it via the ip.risk field, structured logs carry it as risk_score,
// and attack reports summarise it (average, max, sample count).
//
// Weights (fixed, documented here so operators can reason about the
// score; there are no hidden inputs):
//
//	Base suspicion level: stage 0 -> 0, stage 1 -> 10, stage 2 -> 30,
//	  stage 3 -> 50, stage 4+ -> 70. The level is the stage the
//	  request arrived at, before firewall rules run.
//	Fingerprint trust: known browser -10, bot-listed fingerprint
//	  +25, unknown fingerprint +15. In Cloudflare mode there is no
//	  TLS fingerprint and the browser is reported as "Cloudflare",
//	  which counts as known (no penalty, no bonus).
//	IP reputation: listed on the local blocklist or feed +25.
//	Shared reputation (cross-domain, Batch 5 item 3): +15 when
//	  another domain on this proxy recently blocked the same IP
//	  or fingerprint.
//	Timing anomaly (Batch 5 item 4): +20 when the IP's request
//	  timing looks inhumanly regular or bursty.
//	Challenge failures: more than 10 failed verifications +10,
//	  more than 50 +20.
//	High-risk geography (operator-configured only): +15 when the
//	  country matches riskHighRiskCountries, +15 when the ASN
//	  matches riskHighRiskASNs. With no lists configured (the
//	  default) geography contributes nothing: an unconfigured
//	  database or a missing record is never penalised.
//
// The result is clamped to 0-100. Same-request honeypot and
// fake-bot hits are NOT inputs: they raise the suspicion level
// directly after the score is computed, so the score is a
// snapshot of the signals known at evaluation time.
type RiskInputs struct {
	SusLevel           int
	KnownBrowser       bool
	BotListed          bool
	UnknownFingerprint bool
	ReputationListed   bool
	SharedReputation   bool
	TimingAnomaly      bool
	ChallengeFailures  int
	Country            string
	ASN                int
	HighRiskCountries  []string
	HighRiskASNs       []int
}

// ComputeRiskScore returns the composite risk score for one request,
// clamped to 0-100.
func ComputeRiskScore(in RiskInputs) int {
	score := 0
	switch {
	case in.SusLevel <= 0:
		score = 0
	case in.SusLevel == 1:
		score = 10
	case in.SusLevel == 2:
		score = 30
	case in.SusLevel == 3:
		score = 50
	default:
		score = 70
	}

	if in.KnownBrowser {
		score -= 10
	}
	if in.BotListed {
		score += 25
	}
	if in.UnknownFingerprint {
		score += 15
	}
	if in.ReputationListed {
		score += 25
	}
	if in.SharedReputation {
		score += 15
	}
	if in.TimingAnomaly {
		score += 20
	}
	if in.ChallengeFailures > 50 {
		score += 20
	} else if in.ChallengeFailures > 10 {
		score += 10
	}
	for _, country := range in.HighRiskCountries {
		if country != "" && country == in.Country {
			score += 15
			break
		}
	}
	for _, asn := range in.HighRiskASNs {
		if asn != 0 && asn == in.ASN {
			score += 15
			break
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}
