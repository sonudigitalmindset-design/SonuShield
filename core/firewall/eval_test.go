package firewall

import (
	"net"
	"testing"

	"sonushield/core/domains"

	"github.com/kor44/gofilter"
)

func mustFilter(t *testing.T, expr string) *gofilter.Filter {
	t.Helper()
	f, err := gofilter.NewFilter(expr)
	if err != nil {
		t.Fatalf("NewFilter(%q): %v", expr, err)
	}
	return f
}

func testVariables() gofilter.Message {
	return gofilter.Message{
		"ip.src":       net.ParseIP("203.0.113.7"),
		"ip.country":   "US",
		"ip.asn":       12345,
		"ip.risk":      60,
		"http.path":    "/admin",
		"http.method":  "GET",
		"proxy.stage":  1,
		"proxy.attack": false,
	}
}

func TestEvalFirewallRuleActions(t *testing.T) {
	vars := testVariables()

	// Plain integer sets the level and stops: later rules never run.
	settings := domains.DomainSettings{CustomRules: []domains.Rule{
		{Filter: mustFilter(t, `ip.country eq "US"`), Action: "4"},
		{Filter: mustFilter(t, `ip.risk gt 50`), Action: "+10"},
	}}
	if got := EvalFirewallRule(settings, vars, 0); got != 4 {
		t.Fatalf("set-action chain = %d, want 4", got)
	}

	// +N/-N adjust and continue.
	settings = domains.DomainSettings{CustomRules: []domains.Rule{
		{Filter: mustFilter(t, `ip.risk gt 50`), Action: "+2"},
		{Filter: mustFilter(t, `http.path eq "/admin"`), Action: "-1"},
	}}
	if got := EvalFirewallRule(settings, vars, 1); got != 2 {
		t.Fatalf("adjust-action chain = %d, want 2", got)
	}

	// Non-matching rules leave the level alone.
	settings = domains.DomainSettings{CustomRules: []domains.Rule{
		{Filter: mustFilter(t, `ip.country eq "DE"`), Action: "4"},
	}}
	if got := EvalFirewallRule(settings, vars, 1); got != 1 {
		t.Fatalf("non-matching rule changed level to %d", got)
	}

	// No rules: level passes through.
	if got := EvalFirewallRule(domains.DomainSettings{}, vars, 3); got != 3 {
		t.Fatalf("empty rule list = %d, want 3", got)
	}
}

func TestApplyRuleActionMalformed(t *testing.T) {
	// A malformed action leaves the level unchanged and does not stop.
	if got, stop := applyRuleAction("+x", 0, 2); got != 2 || stop {
		t.Fatalf("malformed +x: (%d, %v), want (2, false)", got, stop)
	}
	if got, stop := applyRuleAction("-y", 0, 2); got != 2 || stop {
		t.Fatalf("malformed -y: (%d, %v), want (2, false)", got, stop)
	}
	// NOTE: an empty action string would panic on action[:1].
	// Config and API validation reject empty actions before
	// they reach here (ValidRuleAction), so this is a latent
	// robustness gap, not a reachable path — flagged in the
	// sale-readiness report rather than tested here.
}

func TestCompileEdgeRule(t *testing.T) {
	good, err := CompileEdgeRule(`ip.country eq "US"`, "+1")
	if err != nil {
		t.Fatalf("valid edge rule rejected: %v", err)
	}
	if good.Field != "ip.country" || good.StrVal != "US" {
		t.Fatalf("compiled rule = %+v", good)
	}
	if _, err := CompileEdgeRule(`ip.risk gt 50`, "4"); err != nil {
		t.Fatalf("valid int edge rule rejected: %v", err)
	}
	if _, err := CompileEdgeRule(`ip.src eq 203.0.113.0/24`, "4"); err != nil {
		t.Fatalf("valid CIDR edge rule rejected: %v", err)
	}

	rejected := []struct{ expr, action string }{
		{`ip.country eq "US" and ip.risk gt 10`, "+1"}, // compound
		{`ip.country == "US"`, "+1"},                   // symbolic operator
		{`proxy.attack eq true`, "+1"},                 // boolean field
		{`ip.risk contains 5`, "+1"},                   // contains on int
		{`ip.country eq "US"`, "bogus"},                // bad action
		{`not a rule at all`, "+1"},                    // unparseable
	}
	for _, tc := range rejected {
		if _, err := CompileEdgeRule(tc.expr, tc.action); err == nil {
			t.Fatalf("CompileEdgeRule(%q, %q) accepted, want rejection", tc.expr, tc.action)
		}
	}
}

func TestEvalEdgeRules(t *testing.T) {
	vars := testVariables()
	rule1, err := CompileEdgeRule(`ip.country eq "US"`, "+2")
	if err != nil {
		t.Fatal(err)
	}
	rule2, err := CompileEdgeRule(`ip.risk gt 50`, "4")
	if err != nil {
		t.Fatal(err)
	}
	settings := domains.DomainSettings{EdgeRules: []domains.EdgeRule{rule1, rule2}}
	got, stopped := EvalEdgeRules(settings, vars, 0)
	if got != 4 || !stopped {
		t.Fatalf("edge chain = (%d, %v), want (4, true)", got, stopped)
	}
	matched := MatchedEdgeRules(settings, vars)
	if len(matched) != 2 {
		t.Fatalf("matched = %v, want both rules", matched)
	}

	// A non-matching chain adjusts nothing and does not stop.
	rule3, err := CompileEdgeRule(`ip.country eq "DE"`, "4")
	if err != nil {
		t.Fatal(err)
	}
	got, stopped = EvalEdgeRules(domains.DomainSettings{EdgeRules: []domains.EdgeRule{rule3}}, vars, 1)
	if got != 1 || stopped {
		t.Fatalf("non-matching edge chain = (%d, %v), want (1, false)", got, stopped)
	}
}
