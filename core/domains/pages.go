package domains

// Custom challenge-page templates (Batch 5).
//
// Operators may provide their own HTML for the proof-of-work,
// captcha, and waiting-room pages via the per-domain
// pageTemplates config object. Templates use a fixed placeholder
// set:
//
//   - PoW: {{publicSalt}}, {{challenge}}, {{difficulty}}
//     (all required), {{message}} (optional)
//   - Captcha: {{captchaImage}}, {{maskImage}}, {{publicPart}}
//     (all required), {{message}} (optional)
//   - Waiting room: {{position}} (required), {{message}}
//     (optional)
//
// Placeholders are substituted as data (HTML-escaped) and the
// server appends its fixed solver scripts, so a template can
// never change the challenge flow. <script> tags in a template
// are stripped at load time with a warning. A template missing
// a required placeholder is disabled with a warning and the
// built-in page is served instead. The Turnstile/hCaptcha
// provider page is not customizable.

import (
	"fmt"
	"strings"
)

// PageTemplates holds operator-provided HTML for the challenge
// pages. A nil pointer means no custom templates.
type PageTemplates struct {
	PoW         string `json:"pow"`
	Captcha     string `json:"captcha"`
	WaitingRoom string `json:"waitingRoom"`
}

var powRequiredPlaceholders = []string{"{{publicSalt}}", "{{challenge}}", "{{difficulty}}"}
var captchaRequiredPlaceholders = []string{"{{captchaImage}}", "{{maskImage}}", "{{publicPart}}"}
var waitingRequiredPlaceholders = []string{"{{position}}"}

// ValidatePageTemplates normalizes a domain's templates: script
// tags are stripped and templates missing required placeholders
// are disabled, each with a warning. It returns nil when no
// usable template remains.
func ValidatePageTemplates(name string, t *PageTemplates) *PageTemplates {
	if t == nil {
		return nil
	}
	out := *t
	if out.PoW != "" {
		out.PoW = validateTemplate(name, "pow", out.PoW, powRequiredPlaceholders)
	}
	if out.Captcha != "" {
		out.Captcha = validateTemplate(name, "captcha", out.Captcha, captchaRequiredPlaceholders)
	}
	if out.WaitingRoom != "" {
		out.WaitingRoom = validateTemplate(name, "waitingRoom", out.WaitingRoom, waitingRequiredPlaceholders)
	}
	if out.PoW == "" && out.Captcha == "" && out.WaitingRoom == "" {
		return nil
	}
	return &out
}

func validateTemplate(name, kind, tpl string, required []string) string {
	stripped, removed := stripScriptTags(tpl)
	if removed {
		fmt.Println("[ ! ] [ removed <script> tags from " + kind + " page template for " + name + "; the fixed solver script is appended by the server ]")
	}
	for _, ph := range required {
		if !strings.Contains(stripped, ph) {
			fmt.Println("[ ! ] [ disabling " + kind + " page template for " + name + ": missing required placeholder " + ph + "; built-in page will be used ]")
			return ""
		}
	}
	return stripped
}

// stripScriptTags removes <script ...>...</script> spans
// (case-insensitive) and self-closing <script .../> tags. It
// reports whether anything was removed. Tags whose name merely
// starts with "script" (e.g. <scripts>) are left alone.
func stripScriptTags(s string) (string, bool) {
	lower := strings.ToLower(s)
	removed := false
	var out strings.Builder
	for {
		idx := strings.Index(lower, "<script")
		if idx < 0 {
			out.WriteString(s)
			break
		}
		after := idx + len("<script")
		if after < len(s) {
			c := lower[after]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				out.WriteString(s[:after])
				s = s[after:]
				lower = lower[after:]
				continue
			}
		}
		out.WriteString(s[:idx])
		removed = true
		gt := strings.IndexByte(s[idx:], '>')
		if gt < 0 {
			break
		}
		openTag := s[idx : idx+gt+1]
		rest := s[idx+gt+1:]
		restLower := lower[idx+gt+1:]
		if strings.HasSuffix(openTag, "/>") {
			s = rest
			lower = restLower
			continue
		}
		end := strings.Index(restLower, "</script>")
		if end < 0 {
			break
		}
		s = rest[end+len("</script>"):]
		lower = restLower[end+len("</script>"):]
	}
	return out.String(), removed
}
