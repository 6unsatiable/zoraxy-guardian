package guardian

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

// Evaluate applies the rules in order and returns a Decision.
//
// Order:
//
//  1. Fingerprint ban (cross-IP tracking of malicious signatures)
//  2. Temp ban (set by honeypot or auto-ban escalation)
//  3. IP blocklist
//  4. Host-header blocklist
//  5. Honeypot path match (installs a temp ban as a side-effect)
//  6. IP allowlist (only enforced on hosts where an allow rule applies)
//  7. UA blocklist (with optional ExceptPaths)
//  8. WAF rules
//  9. Rate limit
//
// After any block (other than temp-ban itself, which is already promoted),
// the IP gets a strike towards auto-ban escalation, and if fingerprint
// tracking is enabled, the request fingerprint also gets a strike.
//
// When the resolved address is itself a proxy (traffic through Cloudflare or
// another proxy that is not trusted), matching requests are still blocked but
// the address is never banned, struck or rate limited, because every visitor
// behind that proxy shares it.
func (s *Store) Evaluate(req *plugin.DynamicSniffForwardRequest) Decision {
	s.mu.RLock()
	host := req.Host
	trustedProxies := s.trustedProxies
	fpEnabled := s.cfg.FingerprintTracking.Enabled
	honeypotEnabled := s.cfg.Honeypot.Enabled
	honeypotBanSecs := s.cfg.Honeypot.BanSeconds
	allowRules := s.allowRules
	blockRules := s.blockRules
	uaRules := s.uaRules
	hostBlockRules := s.hostBlockRules
	wafRules := s.wafRules
	wafNames := s.wafRuleNames
	honeypotRules := s.honeypotRules
	limiter := s.limiter
	s.mu.RUnlock()

	ip := clientIP(req, trustedProxies)
	parsedIP := net.ParseIP(ip)
	viaProxy := isProxyAddress(parsedIP, trustedProxies)
	if viaProxy {
		s.noteUntrustedProxy(ip, host)
	}
	key := banKey(ip)

	// Generate fingerprint for cross-IP tracking
	var fingerprint string
	if fpEnabled {
		fingerprint = GenerateFingerprint(req)
	}
	block := func(reason string, status int) Decision {
		return Decision{Block: true, Reason: reason, Status: status, IP: ip}
	}
	strike := func() {
		if !viaProxy {
			s.RecordStrike(key)
		}
		if fpEnabled && fingerprint != "" {
			s.RecordFingerprintStrike(fingerprint)
		}
	}

	// 1. Fingerprint ban (check before IP ban to catch IP-hopping attackers)
	if fpEnabled && fingerprint != "" {
		if banned, _ := s.IsFingerprintBanned(fingerprint); banned {
			return block("fingerprint-ban", http.StatusForbidden)
		}
	}

	// 2. Temp ban
	if !viaProxy {
		if banned, _ := s.IsTempBanned(key); banned {
			return block("temp-ban", http.StatusForbidden)
		}
	}

	// 3. IP blocklist
	if parsedIP != nil {
		for _, r := range blockRules {
			if !HostMatches(host, r.Hosts) {
				continue
			}
			if r.Net.Contains(parsedIP) {
				strike()
				return block("ip-blocklist", http.StatusForbidden)
			}
		}
	}

	// 4. Host-header blocklist
	for _, r := range hostBlockRules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if r.RE.MatchString(host) {
			strike()
			return block("host-blocklist", http.StatusForbidden)
		}
	}

	// 5. Honeypot path match — install temp ban as a side-effect
	if honeypotEnabled {
		path := requestPath(req.RequestURI)
		for _, r := range honeypotRules {
			if !HostMatches(host, r.Hosts) {
				continue
			}
			if r.RE.MatchString(path) {
				if !viaProxy {
					s.AddTempBan(key, time.Duration(honeypotBanSecs)*time.Second)
				}
				return block("honeypot", http.StatusForbidden)
			}
		}
	}

	// 6. Allowlist (only enforced if at least one allow rule applies to this host)
	allowHostScoped := make([]compiledIPRule, 0, len(allowRules))
	for _, r := range allowRules {
		if HostMatches(host, r.Hosts) {
			allowHostScoped = append(allowHostScoped, r)
		}
	}
	if len(allowHostScoped) > 0 {
		allowed := false
		if parsedIP != nil {
			for _, r := range allowHostScoped {
				if r.Net.Contains(parsedIP) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			strike()
			return block("not-allowlisted", http.StatusForbidden)
		}
	}

	// 7. UA blocklist (with ExceptPaths)
	ua := firstHeader(req.Header, "User-Agent")
	for _, r := range uaRules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if pathExempt(req.RequestURI, r.ExceptPaths) {
			continue
		}
		if r.RE.MatchString(ua) {
			strike()
			return block("ua-blocklist", http.StatusForbidden)
		}
	}

	// 8. WAF rules
	if hit := wafCheck(req, host, wafRules, wafNames); hit != "" {
		strike()
		return block("waf-"+hit, http.StatusForbidden)
	}

	// 9. Rate limit
	if limiter != nil && parsedIP != nil && !viaProxy {
		if !limiter.allow(key) {
			strike()
			return block("rate-limit", http.StatusTooManyRequests)
		}
	}

	return Decision{Block: false, IP: ip}
}

// pathExempt returns true if requestURI contains any of the literal except
// paths as a substring. Used by UA rules to skip when the request is going
// to (say) /robots.txt.
func pathExempt(requestURI string, exceptPaths []string) bool {
	if len(exceptPaths) == 0 {
		return false
	}
	path := strings.ToLower(requestPath(requestURI))
	for _, p := range exceptPaths {
		if p == "" {
			continue
		}
		if strings.Contains(path, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// requestPath returns the path component of a request target without query
// or fragment data. Path-specific rules must not be bypassed or triggered by
// values embedded in a query string.
func requestPath(requestURI string) string {
	if u, err := url.ParseRequestURI(requestURI); err == nil && u.Path != "" {
		return u.Path
	}
	if i := strings.IndexAny(requestURI, "?#"); i >= 0 {
		return requestURI[:i]
	}
	return requestURI
}

func wafCheck(req *plugin.DynamicSniffForwardRequest, host string, rules []compiledRegexRule, names []string) string {
	target := req.RequestURI + " " + req.URL
	for k, vs := range req.Header {
		if strings.EqualFold(k, "cookie") || strings.EqualFold(k, "referer") {
			target += " " + strings.Join(vs, " ")
		}
	}
	// Attackers percent-encode payloads (%3Cscript, ..%2f, double-encoded
	// %252e) to get past literal patterns, so rules also see the decoded form.
	decoded := percentDecode(percentDecode(target))
	for i, r := range rules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if r.RE.MatchString(target) || (decoded != target && r.RE.MatchString(decoded)) {
			return names[i]
		}
	}
	return ""
}

// percentDecode decodes valid %XX escapes and leaves anything malformed as
// it is, so one bad escape can't hide the rest of a payload the way a strict
// decoder's error would. '+' is left alone (it is only a space in forms).
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func remoteIP(addr string) net.IP {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.TrimSpace(addr))
}

func ipInRules(ip net.IP, rules []compiledIPRule) bool {
	for _, rule := range rules {
		if rule.Net.Contains(ip) {
			return true
		}
	}
	return false
}

func firstHeader(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
