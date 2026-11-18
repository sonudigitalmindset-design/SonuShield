package domains

// Precompiled edge rules (Batch 6). An EdgeRule is a single
// comparison — one field, one operator, one literal — compiled
// once at load time by firewall.CompileEdgeRule and evaluated
// without the gofilter interpreter. The compiler accepts only
// the restricted grammar documented in core/firewall/edge.go;
// anything else stays a general firewall rule.
//
// Matches replicates gofilter's comparison semantics exactly,
// including its quirks, so an edge rule behaves identically to
// the equivalent general rule:
//
//   - Comparisons are strictly typed: a value whose Go type does
//     not match the field's kind never matches (except through
//     `ne`, see below).
//   - `ne` is parsed by gofilter as NOT(eq), so a missing field
//     or a type mismatch makes `ne` TRUE. Matches reproduces
//     that: ne is the negation of the eq outcome.
//   - String literals parse as gofilter parses them: Go unquoting
//     first, then colon-hex bytes, then the raw text. The parse
//     decides the literal's byte content (a bare "aa" is the
//     single byte 0xaa, not the two characters); values compare
//     as strings either way.
//   - A []byte message value never matches any comparison:
//     gofilter iterates slice values element-wise before the
//     comparison node runs, and a uint8 element matches no
//     literal. Matches reproduces that by accepting string
//     values only. (No message value is a slice in production;
//     the rule exists so the two evaluators agree on every
//     input, not just realistic ones.)
//   - IP equality uses net.IP.Equal; a CIDR literal tests
//     containment. IP ordering compares 16-byte forms, except
//     `le`, which gofilter compares without the To16 expansion —
//     reproduced here deliberately, not fixed.
//   - A CIDR literal in an ordering comparison compares against
//     the network address only; the mask is ignored, as in
//     gofilter.
//
// The message is assumed to hold scalar values, as the middleware
// constructs it; gofilter's slice iteration (applyRange) is
// replicated only for the []byte case (never matches, see above),
// because no message value is ever any other slice type.

import (
	"bytes"
	"net"

	"github.com/kor44/gofilter"
)

// EdgeOp is a fast-path comparison operator.
type EdgeOp int

const (
	EdgeOpEq EdgeOp = iota
	EdgeOpNe
	EdgeOpGt
	EdgeOpGe
	EdgeOpLt
	EdgeOpLe
	EdgeOpContains
)

// EdgeFieldKind classifies a rule field by the type gofilter
// parses its literals as. Boolean fields have no kind: gofilter
// boolean comparisons never match, and the edge compiler rejects
// them loudly instead of compiling dead rules.
type EdgeFieldKind int

const (
	EdgeFieldString EdgeFieldKind = iota
	EdgeFieldInt
	EdgeFieldIP
)

// EdgeRule is one precompiled edge rule. Expression and Action
// are the original config values (for logging and reporting);
// the remaining fields are the compiled comparison.
type EdgeRule struct {
	Expression string
	Action     string
	Field      string
	Op         EdgeOp
	Kind       EdgeFieldKind
	StrVal     string
	IntVal     int
	IPVal      net.IP
	IPNet      *net.IPNet
	IsCIDR     bool
}

// Matches reports whether the rule matches the request variables,
// with gofilter-identical semantics (see the package note above).
func (r EdgeRule) Matches(variables gofilter.Message) bool {
	value, present := variables[r.Field]
	switch r.Op {
	case EdgeOpNe:
		return !r.matchEq(value, present)
	case EdgeOpEq:
		return r.matchEq(value, present)
	default:
		return r.matchOrdering(value, present)
	}
}

// matchEq is the gofilter `eq` outcome: false for a missing field
// or a type mismatch, otherwise the kind-specific equality.
func (r EdgeRule) matchEq(value interface{}, present bool) bool {
	if !present {
		return false
	}
	switch r.Kind {
	case EdgeFieldString:
		x, ok := value.(string)
		return ok && x == r.StrVal
	case EdgeFieldInt:
		x, ok := value.(int)
		return ok && x == r.IntVal
	case EdgeFieldIP:
		x, ok := value.(net.IP)
		if !ok {
			return false
		}
		if r.IsCIDR {
			return r.IPNet.Contains(x)
		}
		return x.Equal(r.IPVal)
	}
	return false
}

// matchOrdering is the gofilter gt/ge/lt/le/contains outcome:
// false for a missing field or a type mismatch, otherwise the
// kind-specific comparison.
func (r EdgeRule) matchOrdering(value interface{}, present bool) bool {
	if !present {
		return false
	}
	switch r.Kind {
	case EdgeFieldString:
		x, ok := value.(string)
		if !ok {
			return false
		}
		return compareEdgeBytes([]byte(x), []byte(r.StrVal), r.Op)
	case EdgeFieldInt:
		x, ok := value.(int)
		if !ok {
			return false
		}
		return compareEdgeInts(x, r.IntVal, r.Op)
	case EdgeFieldIP:
		x, ok := value.(net.IP)
		if !ok {
			return false
		}
		return r.compareEdgeIP(x)
	}
	return false
}

// compareEdgeBytes applies an ordering operator (or contains) to
// byte slices, as gofilter's []byte/string comparisons do.
func compareEdgeBytes(value, literal []byte, op EdgeOp) bool {
	switch op {
	case EdgeOpGt:
		return bytes.Compare(value, literal) == 1
	case EdgeOpGe:
		return bytes.Compare(value, literal) >= 0
	case EdgeOpLt:
		return bytes.Compare(value, literal) == -1
	case EdgeOpLe:
		return bytes.Compare(value, literal) <= 0
	case EdgeOpContains:
		return bytes.Contains(value, literal)
	}
	return false
}

// compareEdgeInts applies an ordering operator to integers.
// Contains never matches an integer field (the compiler rejects
// it); the default here is defensive.
func compareEdgeInts(value, literal int, op EdgeOp) bool {
	switch op {
	case EdgeOpGt:
		return value > literal
	case EdgeOpGe:
		return value >= literal
	case EdgeOpLt:
		return value < literal
	case EdgeOpLe:
		return value <= literal
	}
	return false
}

// compareEdgeIP applies an ordering operator to an IP value. The
// comparison target is the literal IP, or the network address
// for a CIDR literal (the mask is ignored, as in gofilter). The
// `le` case deliberately omits the To16 expansion, reproducing
// gofilter's nodeLe behavior; gt/ge/lt expand both sides.
func (r EdgeRule) compareEdgeIP(value net.IP) bool {
	target := r.IPVal
	if r.IsCIDR {
		target = r.IPNet.IP
	}
	switch r.Op {
	case EdgeOpGt:
		return bytes.Compare([]byte(value.To16()), []byte(target)) == 1
	case EdgeOpGe:
		return bytes.Compare([]byte(value.To16()), []byte(target)) >= 0
	case EdgeOpLt:
		return bytes.Compare([]byte(value.To16()), []byte(target)) == -1
	case EdgeOpLe:
		return bytes.Compare([]byte(value), []byte(target)) <= 0
	}
	return false
}
