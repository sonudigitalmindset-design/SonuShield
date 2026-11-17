package firewall

// EffectivePoWDifficulty returns the Stage 2 proof-of-work difficulty to
// serve for the current load.
//
// The difficulty scales linearly with the domain's bypassed requests per
// second between lowThreshold (BypassStage1) and highThreshold
// (BypassStage2): at or below the low threshold the minimum applies, at or
// above the high threshold the maximum applies. This keeps the check fast
// for legitimate visitors under normal load and makes it progressively
// harder for bots as an attack that bypasses Stage 1 grows.
//
//   - base is the configured stage2Difficulty. When min is unset (<= 0) it
//     defaults to base, so adaptive mode never goes below the configured
//     difficulty unless the operator asks for a lower floor. When max is
//     unset (<= 0) it defaults to base+3.
//   - The result is always clamped to [1, 16]. Each +1 multiplies the
//     client's work roughly 16x (one more hex character to brute-force),
//     so 16 is a deliberately conservative ceiling.
//   - When the thresholds are misconfigured (high <= low), the base
//     difficulty is returned, clamped to [min, max].
//
// The caller additionally clamps the result below the length of the
// encrypted challenge token, so a misconfiguration can never panic the
// slice in the challenge handler.
func EffectivePoWDifficulty(base, min, max, bypassedRPS, lowThreshold, highThreshold int) int {
	if min <= 0 {
		min = base
	}
	if max <= 0 {
		max = base + 3
	}
	if max < min {
		max = min
	}
	if min < 1 {
		min = 1
	}
	if max < 1 {
		max = 1
	}
	if max > 16 {
		max = 16
	}
	if min > max {
		min = max
	}

	if highThreshold <= lowThreshold {
		if base < min {
			return min
		}
		if base > max {
			return max
		}
		return base
	}
	if bypassedRPS <= lowThreshold {
		return min
	}
	if bypassedRPS >= highThreshold {
		return max
	}

	span := highThreshold - lowThreshold
	progress := bypassedRPS - lowThreshold
	return min + (max-min)*progress/span
}
