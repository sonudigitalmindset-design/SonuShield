package firewall

import "testing"

// The documented weights in risk.go are the contract: a clean
// known-browser request at stage 0 scores 0, and each signal
// adds exactly its documented weight.
func TestComputeRiskScoreClean(t *testing.T) {
	if got := ComputeRiskScore(RiskInputs{KnownBrowser: true}); got != 0 {
		t.Fatalf("clean request scored %d, want 0 (clamped)", got)
	}
	if got := ComputeRiskScore(RiskInputs{}); got != 0 {
		t.Fatalf("empty inputs scored %d, want 0", got)
	}
}

func TestComputeRiskScoreWeights(t *testing.T) {
	cases := []struct {
		name string
		in   RiskInputs
		want int
	}{
		{"stage1", RiskInputs{SusLevel: 1}, 10},
		{"stage2", RiskInputs{SusLevel: 2}, 30},
		{"stage3", RiskInputs{SusLevel: 3}, 50},
		{"stage4", RiskInputs{SusLevel: 4}, 70},
		{"stage9", RiskInputs{SusLevel: 9}, 70},
		{"botListed", RiskInputs{BotListed: true}, 25},
		{"unknownFp", RiskInputs{UnknownFingerprint: true}, 15},
		{"reputation", RiskInputs{ReputationListed: true}, 25},
		{"sharedRep", RiskInputs{SharedReputation: true}, 15},
		{"timing", RiskInputs{TimingAnomaly: true}, 20},
		{"behavior", RiskInputs{BehaviorBot: true}, 15},
		{"failures11", RiskInputs{ChallengeFailures: 11}, 10},
		{"failures51", RiskInputs{ChallengeFailures: 51}, 20},
		{"failures10", RiskInputs{ChallengeFailures: 10}, 0},
		{"country", RiskInputs{Country: "XX", HighRiskCountries: []string{"XX"}}, 15},
		{"countryMiss", RiskInputs{Country: "YY", HighRiskCountries: []string{"XX"}}, 0},
		{"countryUnconfigured", RiskInputs{Country: "XX"}, 0},
		{"asn", RiskInputs{ASN: 12345, HighRiskASNs: []int{12345}}, 15},
		{"combined", RiskInputs{SusLevel: 2, BotListed: true, TimingAnomaly: true, ChallengeFailures: 20}, 85},
	}
	for _, tc := range cases {
		if got := ComputeRiskScore(tc.in); got != tc.want {
			t.Fatalf("%s: score %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestComputeRiskScoreClamp(t *testing.T) {
	everything := RiskInputs{
		SusLevel: 9, BotListed: true, UnknownFingerprint: true,
		ReputationListed: true, SharedReputation: true,
		TimingAnomaly: true, BehaviorBot: true, ChallengeFailures: 100,
		Country: "XX", HighRiskCountries: []string{"XX"},
		ASN: 1, HighRiskASNs: []int{1},
	}
	if got := ComputeRiskScore(everything); got != 100 {
		t.Fatalf("maximal inputs scored %d, want clamped 100", got)
	}
}
