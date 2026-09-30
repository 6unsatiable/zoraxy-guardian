package guardian

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
)

// Subset of Cloudflare's wirefilter expression language that translates to
// Guardian primitives. The parser is intentionally narrow — it covers the
// constructs found in typical "block scanner paths" and "block AI bots"
// rules. Anything it doesn't recognize is reported as a warning so the user
// knows what couldn't be imported.

// CFImportResult is what the parser produces. Empty slices are valid.
type CFImportResult struct {
	Honeypot      []ScopedEntry `json:"honeypot_paths"`
	UABlocklist   []ScopedEntry `json:"ua_blocklist"`
	HostBlocklist []ScopedEntry `json:"host_blocklist"`
	WAFRules      []WAFRule     `json:"waf_rules"`
	IPBlocklist   []ScopedEntry `json:"ip_blocklist"`
	Warnings      []string      `json:"warnings"`
}

// ParseCloudflareRules parses one or more Cloudflare expressions and
// returns the resulting Guardian rule additions. Multiple expressions can
// be concatenated (the user often pastes two rules back-to-back). Each
// top-level expression is processed independently.
func ParseCloudflareRules(src string) (CFImportResult, error) {
	res := CFImportResult{
		Honeypot:      []ScopedEntry{},
		UABlocklist:   []ScopedEntry{},
		HostBlocklist: []ScopedEntry{},
		WAFRules:      []WAFRule{},
		IPBlocklist:   []ScopedEntry{},
		Warnings:      []string{},
	}
	src = strings.TrimSpace(src)
	if src == "" {
		return res, nil
	}
	tokens, err := cfTokenize(src)
	if err != nil {
		return res, err
	}
	p := &cfParser{tokens: tokens}
	for !p.atEnd() {
		expr, err := p.parseExpr()
		if err != nil {
			return res, err
		}
		translate(expr, nil, &res)
	}
	return res, nil
}

// --- AST ---

type cfNode interface{ isCFNode() }

type cfBinary struct {
	Op    string // "and" | "or"
	Left  cfNode
	Right cfNode
}
type cfNot struct{ Inner cfNode }
type cfPredicate struct {
	Field string // canonical dotted form, e.g. "http.request.uri.path"
	Op    string // contains | eq | ne | matches | in
	Value string // string literal, or empty if multi-valued
	Set   []string
}

func (cfBinary) isCFNode()    {}
func (cfNot) isCFNode()       {}
func (cfPredicate) isCFNode() {}

// --- tokenizer ---

type cfTokenKind int

const (
	tkIdent cfTokenKind = iota
	tkString
	tkNumber
	tkLParen
	tkRParen
	tkLBrace
	tkRBrace
	tkLBracket
	tkRBracket
	tkDot
)

type cfToken struct {
	Kind cfTokenKind
	Val  string
	Pos  int
}

func cfTokenize(src string) ([]cfToken, error) {
	var out []cfToken
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, cfToken{tkLParen, "(", i})
			i++
		case c == ')':
			out = append(out, cfToken{tkRParen, ")", i})
			i++
		case c == '{':
			out = append(out, cfToken{tkLBrace, "{", i})
			i++
		case c == '}':
			out = append(out, cfToken{tkRBrace, "}", i})
			i++
		case c == '[':
			out = append(out, cfToken{tkLBracket, "[", i})
			i++
		case c == ']':
			out = append(out, cfToken{tkRBracket, "]", i})
			i++
		case c == '.':
			out = append(out, cfToken{tkDot, ".", i})
			i++
		case c == ',':
			// Cloudflare accepts commas between set members; ignore them.
			i++
		case c == '$':
			return nil, fmt.Errorf("lists ($name at offset %d) can't be imported; paste the list's entries instead", i)
		case strings.HasPrefix(src[i:], "=="), strings.HasPrefix(src[i:], "!="),
			strings.HasPrefix(src[i:], "&&"), strings.HasPrefix(src[i:], "||"),
			strings.HasPrefix(src[i:], "^^"), strings.HasPrefix(src[i:], ">="),
			strings.HasPrefix(src[i:], "<="):
			// Symbolic operators are normalized to the English ones.
			out = append(out, cfToken{tkIdent, cfSymbolicOps[src[i:i+2]], i})
			i += 2
		case c == '~' || c == '!' || c == '>' || c == '<':
			out = append(out, cfToken{tkIdent, cfSymbolicOps[string(c)], i})
			i++
		case c == 'r' && i+1 < len(src) && (src[i+1] == '"' || src[i+1] == '#'):
			// Raw string: r"..." or r#"..."# (no escape processing).
			j := i + 1
			hashes := 0
			for j < len(src) && src[j] == '#' {
				hashes++
				j++
			}
			if j >= len(src) || src[j] != '"' {
				return nil, fmt.Errorf("malformed raw string at offset %d", i)
			}
			closing := "\"" + strings.Repeat("#", hashes)
			end := strings.Index(src[j+1:], closing)
			if end < 0 {
				return nil, fmt.Errorf("unterminated raw string at offset %d", i)
			}
			out = append(out, cfToken{tkString, src[j+1 : j+1+end], i})
			i = j + 1 + end + len(closing)
		case isHexIPv6Start(src[i:]):
			// An IPv6 literal that starts with a letter, e.g. fe80::/10.
			j := i
			for j < len(src) && (isHexDigit(src[j]) || src[j] == ':' || src[j] == '.' || src[j] == '/') {
				j++
			}
			out = append(out, cfToken{tkNumber, src[i:j], i})
			i = j
		case c == '"':
			// String literal with backslash escapes.
			j := i + 1
			var buf strings.Builder
			for j < len(src) && src[j] != '"' {
				if src[j] == '\\' && j+1 < len(src) {
					buf.WriteByte(src[j+1])
					j += 2
					continue
				}
				buf.WriteByte(src[j])
				j++
			}
			if j >= len(src) {
				return nil, fmt.Errorf("unterminated string at offset %d", i)
			}
			out = append(out, cfToken{tkString, buf.String(), i})
			i = j + 1
		case unicode.IsLetter(rune(c)) || c == '_':
			j := i
			for j < len(src) && (unicode.IsLetter(rune(src[j])) || unicode.IsDigit(rune(src[j])) || src[j] == '_' || src[j] == '-') {
				j++
			}
			out = append(out, cfToken{tkIdent, src[i:j], i})
			i = j
		case unicode.IsDigit(rune(c)):
			// A digit-led literal: number, IPv4, IPv6, or CIDR.
			// Allow hex digits and the chars that appear in IPs/CIDR.
			j := i
			for j < len(src) {
				ch := src[j]
				if unicode.IsDigit(rune(ch)) ||
					(ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') ||
					ch == '.' || ch == ':' || ch == '/' {
					j++
					continue
				}
				break
			}
			out = append(out, cfToken{tkNumber, src[i:j], i})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q at offset %d", c, i)
		}
	}
	return out, nil
}

var cfSymbolicOps = map[string]string{
	"==": "eq", "!=": "ne", "&&": "and", "||": "or", "^^": "xor",
	">=": "ge", "<=": "le", ">": "gt", "<": "lt", "~": "matches", "!": "not",
}

func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// isHexIPv6Start reports whether s begins with hex digits followed by ':'
// (an IPv6 literal like "fe80::1" that would otherwise lex as an identifier).
func isHexIPv6Start(s string) bool {
	j := 0
	for j < len(s) && j < 4 && isHexDigit(s[j]) {
		j++
	}
	return j > 0 && j < len(s) && s[j] == ':' && !('0' <= s[0] && s[0] <= '9')
}

// --- parser ---

type cfParser struct {
	tokens []cfToken
	pos    int
}

func (p *cfParser) atEnd() bool { return p.pos >= len(p.tokens) }
func (p *cfParser) peek() (cfToken, bool) {
	if p.atEnd() {
		return cfToken{}, false
	}
	return p.tokens[p.pos], true
}
func (p *cfParser) advance() (cfToken, bool) {
	t, ok := p.peek()
	if ok {
		p.pos++
	}
	return t, ok
}
func (p *cfParser) match(kind cfTokenKind, val string) bool {
	t, ok := p.peek()
	if !ok || t.Kind != kind {
		return false
	}
	if val != "" && !strings.EqualFold(t.Val, val) {
		return false
	}
	p.pos++
	return true
}
func (p *cfParser) expect(kind cfTokenKind, val, what string) (cfToken, error) {
	t, ok := p.peek()
	if !ok {
		return cfToken{}, fmt.Errorf("expected %s, got end of input", what)
	}
	if t.Kind != kind || (val != "" && !strings.EqualFold(t.Val, val)) {
		return cfToken{}, fmt.Errorf("expected %s at offset %d, got %q", what, t.Pos, t.Val)
	}
	p.pos++
	return t, nil
}

func (p *cfParser) parseExpr() (cfNode, error) { return p.parseOr() }

func (p *cfParser) parseOr() (cfNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.Kind != tkIdent || !strings.EqualFold(t.Val, "or") {
			break
		}
		p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = cfBinary{Op: "or", Left: left, Right: right}
	}
	return left, nil
}

func (p *cfParser) parseAnd() (cfNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.Kind != tkIdent || !strings.EqualFold(t.Val, "and") {
			break
		}
		p.advance()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = cfBinary{Op: "and", Left: left, Right: right}
	}
	return left, nil
}

func (p *cfParser) parseUnary() (cfNode, error) {
	if p.match(tkIdent, "not") {
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return cfNot{Inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *cfParser) parsePrimary() (cfNode, error) {
	if p.match(tkLParen, "") {
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkRParen, "", "')'"); err != nil {
			return nil, err
		}
		return inner, nil
	}
	return p.parsePredicate()
}

func (p *cfParser) parsePredicate() (cfNode, error) {
	// Transformation functions only change case/encoding; the rules they
	// produce are already case-insensitive, so the wrapper is unwrapped.
	if t, ok := p.peek(); ok && t.Kind == tkIdent && p.pos+1 < len(p.tokens) && p.tokens[p.pos+1].Kind == tkLParen {
		switch strings.ToLower(t.Val) {
		case "lower", "upper", "url_decode":
			p.pos += 2
			inner, err := p.parsePredicateField()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkRParen, "", "')' after function argument"); err != nil {
				return nil, err
			}
			return p.parseOperatorAndValue(inner)
		default:
			return nil, fmt.Errorf("unsupported function %s() at offset %d", t.Val, t.Pos)
		}
	}
	field, err := p.parsePredicateField()
	if err != nil {
		return nil, err
	}
	return p.parseOperatorAndValue(field)
}

func (p *cfParser) parsePredicateField() (string, error) {
	// Parse field: ident ('.' ident)* ('[' string ']')?
	first, err := p.expect(tkIdent, "", "field name")
	if err != nil {
		return "", err
	}
	parts := []string{first.Val}
	for p.match(tkDot, "") {
		t, err := p.expect(tkIdent, "", "field name after '.'")
		if err != nil {
			return "", err
		}
		parts = append(parts, t.Val)
	}
	field := strings.Join(parts, ".")
	// Optional header subscript like http.request.headers["x-foo"]
	if p.match(tkLBracket, "") {
		t, err := p.expect(tkString, "", "header name in brackets")
		if err != nil {
			return "", err
		}
		field += "[" + t.Val + "]"
		if _, err := p.expect(tkRBracket, "", "']'"); err != nil {
			return "", err
		}
	}
	return field, nil
}

func (p *cfParser) parseOperatorAndValue(field string) (cfNode, error) {
	// A bare boolean field (cf.client.bot, ssl) has no operator.
	next, ok := p.peek()
	if !ok || next.Kind == tkRParen || (next.Kind == tkIdent &&
		(strings.EqualFold(next.Val, "and") || strings.EqualFold(next.Val, "or") || strings.EqualFold(next.Val, "xor"))) {
		return cfPredicate{Field: field, Op: "is-true"}, nil
	}

	// Operator
	opTok, err := p.expect(tkIdent, "", "operator")
	if err != nil {
		return nil, err
	}
	op := strings.ToLower(opTok.Val)
	if op == "strict" && p.match(tkIdent, "wildcard") {
		op = "strict wildcard"
	}

	// Value
	pred := cfPredicate{Field: field, Op: op}
	if op == "in" {
		if _, err := p.expect(tkLBrace, "", "'{'"); err != nil {
			return nil, err
		}
		for {
			t, ok := p.peek()
			if !ok {
				return nil, fmt.Errorf("unterminated 'in' set")
			}
			if t.Kind == tkRBrace {
				p.advance()
				break
			}
			if t.Kind == tkNumber && p.pos+2 < len(p.tokens) && p.tokens[p.pos+1].Kind == tkDot && p.tokens[p.pos+2].Kind == tkDot {
				return nil, fmt.Errorf("port/number ranges (a..b) are not supported in 'in' sets")
			}
			if t.Kind != tkString && t.Kind != tkNumber && t.Kind != tkIdent {
				return nil, fmt.Errorf("unexpected token in 'in' set: %q", t.Val)
			}
			pred.Set = append(pred.Set, t.Val)
			p.advance()
		}
		return pred, nil
	}
	tok, ok := p.advance()
	if !ok {
		return nil, fmt.Errorf("expected value after operator %q", op)
	}
	if tok.Kind == tkLParen || tok.Kind == tkRParen || tok.Kind == tkLBrace {
		return nil, fmt.Errorf("expected value after operator %q at offset %d", op, tok.Pos)
	}
	pred.Value = tok.Val
	return pred, nil
}

// --- translator ---

// translate walks the AST and produces Guardian config additions.
// constraints is the set of path-ne predicates accumulated from enclosing
// AND nodes; they become ExceptPaths on UA rules.
func translate(node cfNode, constraints []cfPredicate, res *CFImportResult) {
	switch n := node.(type) {
	case cfBinary:
		if strings.EqualFold(n.Op, "and") {
			translateAnd(n, constraints, res)
			return
		}
		// 'or' — translate each side independently.
		translate(n.Left, constraints, res)
		translate(n.Right, constraints, res)
	case cfNot:
		// Translate inner but flag the warning — Guardian doesn't have
		// a global "negation" wrapper around a rule.
		res.Warnings = append(res.Warnings, "skipping NOT expression (Guardian has no global rule negation)")
		_ = n
	case cfPredicate:
		translatePredicate(n, constraints, res)
	}
}

// translateAnd only imports conjunctions that Guardian can preserve exactly:
// one UA predicate plus zero or more path-ne exceptions. Splitting other AND
// expressions into separate rules would broaden a Cloudflare block rule and
// can unexpectedly block legitimate traffic.
func translateAnd(n cfBinary, constraints []cfPredicate, res *CFImportResult) {
	predicates, ok := flattenAnd(n)
	if ok {
		cs := append([]cfPredicate{}, constraints...)
		var actions []cfPredicate
		for _, p := range predicates {
			if isPathField(p.Field) && strings.EqualFold(p.Op, "ne") {
				cs = append(cs, p)
				continue
			}
			actions = append(actions, p)
		}
		if len(actions) == 1 && isUAField(actions[0].Field) &&
			(strings.EqualFold(actions[0].Op, "contains") || strings.EqualFold(actions[0].Op, "matches")) {
			translatePredicate(actions[0], cs, res)
			return
		}
	} else if exceptions, action, valid := splitUAExceptionAnd(n); valid {
		cs := append(append([]cfPredicate{}, constraints...), exceptions...)
		translate(action, cs, res)
		return
	}
	res.Warnings = append(res.Warnings, "skipping AND expression — Guardian cannot preserve this grouped condition")
}

// splitUAExceptionAnd supports the common CF pattern
// path ne "/robots.txt" and (ua contains "a" or ua contains "b").
func splitUAExceptionAnd(n cfBinary) ([]cfPredicate, cfNode, bool) {
	parts := flattenAndNodes(n)
	var exceptions []cfPredicate
	var action cfNode
	for _, part := range parts {
		if p, ok := part.(cfPredicate); ok && isPathField(p.Field) && strings.EqualFold(p.Op, "ne") {
			exceptions = append(exceptions, p)
			continue
		}
		if action != nil || !isUAOrExpression(part) {
			return nil, nil, false
		}
		action = part
	}
	return exceptions, action, action != nil && len(exceptions) > 0
}

func flattenAndNodes(n cfNode) []cfNode {
	if b, ok := n.(cfBinary); ok && strings.EqualFold(b.Op, "and") {
		return append(flattenAndNodes(b.Left), flattenAndNodes(b.Right)...)
	}
	return []cfNode{n}
}

func isUAOrExpression(n cfNode) bool {
	switch v := n.(type) {
	case cfPredicate:
		return isUAField(v.Field) && (strings.EqualFold(v.Op, "contains") || strings.EqualFold(v.Op, "matches"))
	case cfBinary:
		return strings.EqualFold(v.Op, "or") && isUAOrExpression(v.Left) && isUAOrExpression(v.Right)
	default:
		return false
	}
}

func flattenAnd(n cfNode) ([]cfPredicate, bool) {
	switch v := n.(type) {
	case cfPredicate:
		return []cfPredicate{v}, true
	case cfBinary:
		if !strings.EqualFold(v.Op, "and") {
			return nil, false
		}
		left, ok := flattenAnd(v.Left)
		if !ok {
			return nil, false
		}
		right, ok := flattenAnd(v.Right)
		if !ok {
			return nil, false
		}
		return append(left, right...), true
	default:
		return nil, false
	}
}

func exceptionPaths(constraints []cfPredicate) []string {
	if len(constraints) == 0 {
		return nil
	}
	out := make([]string, 0, len(constraints))
	for _, c := range constraints {
		out = append(out, c.Value)
	}
	return out
}

func translatePredicate(p cfPredicate, constraints []cfPredicate, res *CFImportResult) {
	field := p.Field
	op := strings.ToLower(p.Op)
	val := p.Value

	switch {
	case isPathField(field) && op == "contains":
		// Path substring → honeypot path (matches anywhere in the path).
		// Stricter than the Cloudflare rule: a honeypot hit also bans the
		// client for the honeypot duration.
		res.Honeypot = append(res.Honeypot, ScopedEntry{Value: val})
	case isPathField(field) && op == "eq":
		// Exact path → exact honeypot entry. A plain literal would match
		// anywhere in the path and ban far more than the Cloudflare rule.
		res.Honeypot = append(res.Honeypot, ScopedEntry{Value: "=" + val})
	case isPathField(field) && op == "in":
		for _, v := range p.Set {
			res.Honeypot = append(res.Honeypot, ScopedEntry{Value: "=" + v})
		}
	case isPathField(field) && op == "matches":
		if addRegexWarning(val, res) {
			return
		}
		// A regex over the path only: anchor it to the path segment of the
		// WAF target (which starts with the request URI).
		res.WAFRules = append(res.WAFRules, WAFRule{
			Name:    safeName("cf-path-matches", val),
			Pattern: pathOnlyPattern(val),
			Enabled: true,
		})
	case isPathField(field) && op == "ne":
		// Standalone path ne is only meaningful as an exception inside an
		// AND (handled via constraints).
		res.Warnings = append(res.Warnings, "skipping standalone \"path ne\" — it only works as an exception to a user-agent rule")
	case (isQueryField(field) || isFullURIField(field)) && op == "contains":
		// Query / full-URI substring → WAF rule. (It used to become a
		// honeypot path, which only sees the path and never matched.)
		res.WAFRules = append(res.WAFRules, WAFRule{
			Name:    safeName("cf-uri-contains", val),
			Pattern: "(?i)" + regexp.QuoteMeta(val),
			Enabled: true,
		})
	case (isQueryField(field) || isFullURIField(field)) && op == "matches":
		if addRegexWarning(val, res) {
			return
		}
		res.WAFRules = append(res.WAFRules, WAFRule{
			Name:    safeName("cf-uri-matches", val),
			Pattern: val,
			Enabled: true,
		})
	case isUAField(field) && op == "contains":
		entry := ScopedEntry{
			Value:       "(?i)" + regexp.QuoteMeta(val),
			ExceptPaths: exceptionPaths(constraints),
		}
		res.UABlocklist = append(res.UABlocklist, entry)
	case isUAField(field) && op == "matches":
		if addRegexWarning(val, res) {
			return
		}
		entry := ScopedEntry{
			Value:       val,
			ExceptPaths: exceptionPaths(constraints),
		}
		res.UABlocklist = append(res.UABlocklist, entry)
	case isUAField(field) && (op == "eq" || op == "in"):
		values := p.Set
		if op == "eq" {
			values = []string{val}
		}
		for _, v := range values {
			res.UABlocklist = append(res.UABlocklist, ScopedEntry{
				Value:       "^" + regexp.QuoteMeta(v) + "$",
				ExceptPaths: exceptionPaths(constraints),
			})
		}
	case isHostField(field) && op == "contains":
		res.HostBlocklist = append(res.HostBlocklist, ScopedEntry{
			Value: "(?i)" + regexp.QuoteMeta(val),
		})
	case isHostField(field) && (op == "eq" || op == "in"):
		values := p.Set
		if op == "eq" {
			values = []string{val}
		}
		for _, v := range values {
			res.HostBlocklist = append(res.HostBlocklist, ScopedEntry{
				Value: "(?i)^" + regexp.QuoteMeta(v) + "$",
			})
		}
	case isHostField(field) && op == "matches":
		if addRegexWarning(val, res) {
			return
		}
		res.HostBlocklist = append(res.HostBlocklist, ScopedEntry{Value: val})
	case field == "ip.src" && (op == "in" || op == "eq"):
		values := p.Set
		if op == "eq" {
			values = []string{val}
		}
		for _, v := range values {
			if !validIPOrCIDR(v) {
				res.Warnings = append(res.Warnings, "skipping invalid IP/CIDR \""+v+"\"")
				continue
			}
			res.IPBlocklist = append(res.IPBlocklist, ScopedEntry{Value: v})
		}
	case strings.HasPrefix(field, "http.request.method"):
		res.Warnings = append(res.Warnings,
			"skipping method check — Guardian doesn't filter by HTTP method")
	case strings.HasPrefix(field, "ip.geoip") || strings.HasPrefix(field, "ip.src.") ||
		strings.HasPrefix(field, "cf.") || strings.HasPrefix(field, "ssl"):
		res.Warnings = append(res.Warnings,
			"skipping "+field+" — needs Cloudflare-side signals (GeoIP / ASN / bot score / TLS) Guardian doesn't have")
	default:
		desc := field + " " + op
		if val != "" {
			desc += " \"" + val + "\""
		}
		res.Warnings = append(res.Warnings, "skipping unsupported predicate: "+desc)
	}
}

// addRegexWarning reports (and returns true for) a pattern Go's regexp
// engine can't compile, so preview shows it instead of Apply failing.
func addRegexWarning(pattern string, res *CFImportResult) bool {
	if _, err := regexp.Compile(pattern); err != nil {
		res.Warnings = append(res.Warnings, "skipping regex Guardian can't compile: "+pattern+" ("+err.Error()+")")
		return true
	}
	return false
}

// pathOnlyPattern confines a Cloudflare path regex to the path part of the
// WAF target, which starts with the request URI. "^" in the Cloudflare
// regex means the start of the path.
func pathOnlyPattern(pattern string) string {
	if strings.HasPrefix(pattern, "(?i)") {
		return "(?i)^[^?# ]*?(?:" + strings.TrimPrefix(strings.TrimPrefix(pattern, "(?i)"), "^") + ")"
	}
	if strings.HasPrefix(pattern, "^") {
		return "^(?:" + strings.TrimPrefix(pattern, "^") + ")"
	}
	return "^[^?# ]*?(?:" + pattern + ")"
}

func validIPOrCIDR(v string) bool {
	if _, _, err := net.ParseCIDR(v); err == nil {
		return true
	}
	return net.ParseIP(v) != nil
}

func isPathField(f string) bool {
	f = strings.ToLower(f)
	return f == "http.request.uri.path"
}

// isFullURIField: http.request.uri is path+query; full_uri adds scheme+host.
func isFullURIField(f string) bool {
	f = strings.ToLower(f)
	return f == "http.request.uri" || f == "http.request.full_uri"
}
func isQueryField(f string) bool {
	f = strings.ToLower(f)
	return f == "http.request.uri.query"
}
func isUAField(f string) bool {
	f = strings.ToLower(f)
	return f == "http.user_agent" || f == `http.request.headers["user-agent"]`
}
func isHostField(f string) bool {
	f = strings.ToLower(f)
	return f == "http.host" || f == `http.request.headers["host"]`
}

var safeNameRE = regexp.MustCompile(`[^a-z0-9-]+`)

func safeName(prefix, val string) string {
	s := strings.ToLower(val)
	s = safeNameRE.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 40 {
		s = s[:40]
	}
	if s == "" {
		s = "rule"
	}
	return prefix + "-" + s
}

// --- merge helpers ---

// MergeCFResult appends the parsed rules into cfg, skipping exact duplicates.
// Returns counts of what was added.
type MergeStats struct {
	Honeypot      int `json:"honeypot"`
	UABlocklist   int `json:"ua_blocklist"`
	HostBlocklist int `json:"host_blocklist"`
	WAFRules      int `json:"waf_rules"`
	IPBlocklist   int `json:"ip_blocklist"`
}

func MergeCFResult(cfg *Config, res CFImportResult) MergeStats {
	var stats MergeStats
	stats.Honeypot = mergeScoped(&cfg.Honeypot.Paths, res.Honeypot)
	stats.UABlocklist = mergeScoped(&cfg.UABlocklist, res.UABlocklist)
	stats.HostBlocklist = mergeScoped(&cfg.HostBlocklist, res.HostBlocklist)
	stats.IPBlocklist = mergeScoped(&cfg.IPBlocklist, res.IPBlocklist)

	seenWAF := make(map[string]bool)
	for _, r := range cfg.WAFRules {
		seenWAF[r.Pattern] = true
	}
	for _, r := range res.WAFRules {
		if seenWAF[r.Pattern] {
			continue
		}
		cfg.WAFRules = append(cfg.WAFRules, r)
		seenWAF[r.Pattern] = true
		stats.WAFRules++
	}
	return stats
}

func mergeScoped(target *[]ScopedEntry, incoming []ScopedEntry) int {
	seen := make(map[string]bool)
	for _, e := range *target {
		seen[e.Value] = true
	}
	added := 0
	for _, e := range incoming {
		if seen[e.Value] {
			continue
		}
		*target = append(*target, e)
		seen[e.Value] = true
		added++
	}
	return added
}
