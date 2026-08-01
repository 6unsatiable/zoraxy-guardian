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
func (s *Store) Evaluate(req *plugin.DynamicSniffForwardRequest) Decision {
	s.mu.RLock()
	host := req.Host
	trust := s.cfg.TrustXFF
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

	ip := clientIP(req, trust)
	parsedIP := net.ParseIP(ip)

	// Generate fingerprint for cross-IP tracking
	var fingerprint string
	if fpEnabled {
		fingerprint = GenerateFingerprint(req)
	}

	// 1. Fingerprint ban (check before IP ban to catch IP-hopping attackers)
	if fpEnabled && fingerprint != "" {
		if banned, _ := s.IsFingerprintBanned(fingerprint); banned {
			return Decision{Block: true, Reason: "fingerprint-ban", Status: http.StatusForbidden}
		}
	}

	// 2. Temp ban
	if banned, _ := s.IsTempBanned(ip); banned {
		return Decision{Block: true, Reason: "temp-ban", Status: http.StatusForbidden}
	}

	// 3. IP blocklist
	if parsedIP != nil {
		for _, r := range blockRules {
			if !HostMatches(host, r.Hosts) {
				continue
			}
			if r.Net.Contains(parsedIP) {
				s.RecordStrike(ip)
				if fpEnabled && fingerprint != "" {
					s.RecordFingerprintStrike(fingerprint)
				}
				return Decision{Block: true, Reason: "ip-blocklist", Status: http.StatusForbidden}
			}
		}
	}

	// 4. Host-header blocklist
	for _, r := range hostBlockRules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if r.RE.MatchString(host) {
			s.RecordStrike(ip)
			if fpEnabled && fingerprint != "" {
				s.RecordFingerprintStrike(fingerprint)
			}
			return Decision{Block: true, Reason: "host-blocklist", Status: http.StatusForbidden}
		}
	}

	// 5. Honeypot path match — install temp ban as a side-effect
	if honeypotEnabled {
		for _, r := range honeypotRules {
			if !HostMatches(host, r.Hosts) {
				continue
			}
			if r.RE.MatchString(requestPath(req.RequestURI)) {
				dur := time.Duration(honeypotBanSecs) * time.Second
				s.AddTempBan(ip, dur)
				return Decision{Block: true, Reason: "honeypot", Status: http.StatusForbidden}
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
		if parsedIP == nil {
			s.RecordStrike(ip)
			if fpEnabled && fingerprint != "" {
				s.RecordFingerprintStrike(fingerprint)
			}
			return Decision{Block: true, Reason: "not-allowlisted", Status: http.StatusForbidden}
		}
		allowed := false
		for _, r := range allowHostScoped {
			if r.Net.Contains(parsedIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			s.RecordStrike(ip)
			if fpEnabled && fingerprint != "" {
				s.RecordFingerprintStrike(fingerprint)
			}
			return Decision{Block: true, Reason: "not-allowlisted", Status: http.StatusForbidden}
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
			s.RecordStrike(ip)
			if fpEnabled && fingerprint != "" {
				s.RecordFingerprintStrike(fingerprint)
			}
			return Decision{Block: true, Reason: "ua-blocklist", Status: http.StatusForbidden}
		}
	}

	// 8. WAF rules
	if hit := wafCheck(req, host, wafRules, wafNames); hit != "" {
		s.RecordStrike(ip)
		if fpEnabled && fingerprint != "" {
			s.RecordFingerprintStrike(fingerprint)
		}
		return Decision{Block: true, Reason: "waf-" + hit, Status: http.StatusForbidden}
	}

	// 9. Rate limit
	if limiter != nil && parsedIP != nil {
		if !limiter.allow(parsedIP.String()) {
			s.RecordStrike(ip)
			if fpEnabled && fingerprint != "" {
				s.RecordFingerprintStrike(fingerprint)
			}
			return Decision{Block: true, Reason: "rate-limit", Status: http.StatusTooManyRequests}
		}
	}

	return Decision{Block: false}
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
	for i, r := range rules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if r.RE.MatchString(target) {
			return names[i]
		}
	}
	return ""
}

func clientIP(req *plugin.DynamicSniffForwardRequest, trustXFF bool) string {
	if trustXFF {
		if xff := firstHeader(req.Header, "X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
				return ip.String()
			}
		}
		if xri := firstHeader(req.Header, "X-Real-IP"); xri != "" {
			if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	if ip := net.ParseIP(strings.TrimSpace(req.RemoteAddr)); ip != nil {
		return ip.String()
	}
	return req.RemoteAddr
}

func firstHeader(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
