package guardian

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
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
//  3. IP blocklist, then threat feeds
//  4. Host-header blocklist
//  5. Honeypot path match (installs a temp ban as a side-effect)
//  6. IP allowlist (only enforced on hosts where an allow rule applies)
//  7. UA blocklist (with optional ExceptPaths)
//  8. Bot protection (AI/SEO/headless crawlers, fake search engines)
//  9. WAF rules
//  10. OWASP Core Rule Set (Coraza)
//  11. Challenge hosts: JS proof-of-work for page loads; HTTP-library,
//     fake-browser and crawl-behaviour checks for everything else
//  12. Rate limit
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
	exemptRules := s.exemptRules
	cfOnly := s.cfg.CloudflareOnly
	directHosts := s.cfg.DirectHosts
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
	crs := s.crs
	bots := s.cfg.BotProtection
	chal := s.cfg.Challenge
	chal.Hosts = s.challengeHosts
	chalExempt := s.challengeExempt
	appUARules := s.appUARules
	behavior := s.cfg.Behavior
	feedsOn := s.cfg.ThreatFeeds.Enabled
	maxBody := s.cfg.MaxBodyBytes
	maxBodyHosts := s.cfg.MaxBodyHosts
	s.mu.RUnlock()

	ip := clientIP(req, trustedProxies)
	parsedIP := net.ParseIP(ip)
	// 0. Origin bypass: judged on the direct peer, before any forwarded
	// header is believed. Exempt clients pass so they can't lock themselves out.
	if cfOnly {
		if peer := remoteIP(req.RemoteAddr); peer != nil && !isDirectPeerAllowed(peer, exemptRules, trustedProxies) &&
			!(len(directHosts) > 0 && HostMatches(host, directHosts)) {
			return Decision{Block: true, Reason: "origin-bypass", Status: http.StatusForbidden, IP: ip}
		}
	}
	if parsedIP != nil && ipInRules(parsedIP, exemptRules) {
		return Decision{Block: false, IP: ip}
	}
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
	// strike counts a block towards the IP auto-ban. Only blocks caused by
	// the request's own content (attack signatures) also count against its
	// fingerprint: an IP-, allowlist- or rate-limit block says nothing about
	// the request, and its browser-like fingerprint is shared with innocent
	// visitors.
	strike := func(signature bool) {
		if !viaProxy {
			s.RecordStrike(key)
		}
		if signature && fpEnabled && fingerprint != "" {
			s.RecordFingerprintStrike(fingerprint, key)
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
				strike(false)
				return block("ip-blocklist", http.StatusForbidden)
			}
		}
	}

	// 3b. Threat feeds (hijacked/criminal networks). No strike: the
	// address is blocked on every request anyway.
	if feedsOn && parsedIP != nil && !viaProxy && s.feeds.ips.Load().contains(parsedIP) {
		return block("threat-feed", http.StatusForbidden)
	}

	// 4. Host-header blocklist
	for _, r := range hostBlockRules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if r.RE.MatchString(host) {
			strike(true)
			return block("host-blocklist", http.StatusForbidden)
		}
	}

	// 4b. Declared body size (Zoraxy never shows plugins the body itself).
	if maxBody > 0 && HostMatches(host, maxBodyHosts) {
		if n, err := strconv.ParseInt(strings.TrimSpace(firstHeader(req.Header, "Content-Length")), 10, 64); err == nil && n > maxBody {
			strike(false)
			return block("body-too-large", http.StatusRequestEntityTooLarge)
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
				if fpEnabled && fingerprint != "" {
					s.RecordFingerprintStrike(fingerprint, key)
				}
				return block("honeypot", http.StatusForbidden)
			}
		}
	}

	// 6. Allowlist (only enforced if at least one allow rule applies to this host)
	scoped, allowed := false, false
	for _, r := range allowRules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		scoped = true
		if parsedIP != nil && r.Net.Contains(parsedIP) {
			allowed = true
			break
		}
	}
	if scoped && !allowed {
		strike(false)
		return block("not-allowlisted", http.StatusForbidden)
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
			strike(true)
			return block("ua-blocklist", http.StatusForbidden)
		}
	}

	// 8. Bot protection (User-Agent classes, fake search engines)
	lua := strings.ToLower(ua)
	verifiedEngine := false
	if bots.Enabled {
		if bots.BlockAIScrapers {
			if t := matchAny(lua, *s.feeds.aiBots.Load()); t != "" {
				strike(false)
				return block("ai-scraper", http.StatusForbidden)
			}
		}
		if bots.BlockSEOCrawlers && matchAny(lua, seoBots) != "" {
			strike(false)
			return block("seo-crawler", http.StatusForbidden)
		}
		if bots.BlockHeadless && matchAny(lua, headlessMarkers) != "" {
			strike(false)
			return block("headless-browser", http.StatusForbidden)
		}
		if eng := claimedSearchEngine(lua); eng != nil && parsedIP != nil && !viaProxy {
			if bots.VerifySearchEngines && !s.bots.verify(eng, ip) {
				strike(false)
				return block("fake-search-engine", http.StatusForbidden)
			}
			if bots.BlockSearchEngines {
				return block("search-engine", http.StatusForbidden)
			}
			verifiedEngine = true
		}
	}

	// 9. WAF rules
	if hit := wafCheck(req, host, wafRules, wafNames); hit != "" {
		strike(true)
		return block("waf-"+hit, http.StatusForbidden)
	}

	// 10. OWASP Core Rule Set
	if crs != nil {
		if reason := crsCheck(crs, req, ip); reason != "" {
			strike(true)
			return block(reason, http.StatusForbidden)
		}
	}

	// 11. Browser-facing hosts: challenge page loads, check everything else
	// without user interaction.
	if chal.Enabled && HostMatches(host, chal.Hosts) && len(chal.Hosts) > 0 && !verifiedEngine {
		private := parsedIP == nil || parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast()
		path := requestPath(req.RequestURI)
		hostKey := strings.ToLower(hostOnly(host))
		if path == verifyPath {
			return s.verifyDecision(rawQuery(req.RequestURI), ip, key, ua, hostKey, chal.Difficulty, chal.CookieHours, chal.BindCookieToNetwork)
		}
		hasAuth := false
		for _, h := range authHeaders {
			if firstHeader(req.Header, h) != "" {
				hasAuth = true
				break
			}
		}
		appUA := false
		for _, r := range appUARules {
			if HostMatches(host, r.Hosts) && r.RE.MatchString(ua) {
				appUA = true
				break
			}
		}
		exempt := false
		for _, r := range chalExempt {
			if HostMatches(host, r.Hosts) && r.RE.MatchString(path) {
				exempt = true
				break
			}
		}
		if !private && !hasAuth && !appUA && !s.validCookie(req.Header, hostKey, ua, networkKey(ip, chal.BindCookieToNetwork), time.Now()) {
			isBrowser := looksLikeBrowser(lua)
			if !exempt && !hasStaticExt(path) && (req.Method == http.MethodGet || req.Method == http.MethodHead) && isNavigation(req.Header, isBrowser) {
				return s.challengeDecision(ip, key, ua, hostKey, safeReturnPath(req.RequestURI), chal.Difficulty)
			}
			if bots.Enabled && bots.BlockHTTPLibraries && !exempt && (ua == "" || matchAny(lua, httpLibraries) != "") {
				strike(false)
				return block("http-library", http.StatusForbidden)
			}
			if bots.Enabled && bots.BlockFakeBrowsers && isBrowser &&
				firstHeader(req.Header, "Accept-Language") == "" && firstHeader(req.Header, "Sec-Fetch-Mode") == "" &&
				firstHeader(req.Header, "Sec-Fetch-Site") == "" {
				strike(false)
				return block("fake-browser", http.StatusForbidden)
			}
			if behavior.Enabled && !viaProxy &&
				s.behavior.note(key, path, behavior.MaxPaths, time.Duration(behavior.WindowSeconds)*time.Second, time.Now()) {
				s.AddTempBan(key, time.Duration(behavior.BanSeconds)*time.Second)
				return block("scraping-behavior", http.StatusForbidden)
			}
		}
	}

	// 12. Rate limit
	if limiter != nil && parsedIP != nil && !viaProxy {
		if !limiter.allow(key) {
			strike(false)
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
	// Every header is attack surface (User-Agent and X-Forwarded-* carry
	// Log4Shell and SQLi payloads), except credentials, which legitimately
	// hold arbitrary tokens.
	for k, vs := range req.Header {
		if strings.EqualFold(k, "authorization") || strings.EqualFold(k, "proxy-authorization") {
			continue
		}
		target += " " + strings.Join(vs, " ")
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

// isDirectPeerAllowed reports whether a connection from peer may reach any
// host when CloudflareOnly is on.
func isDirectPeerAllowed(peer net.IP, exemptRules, trustedProxies []compiledIPRule) bool {
	return peer.IsPrivate() || peer.IsLoopback() || peer.IsLinkLocalUnicast() || isCloudflareIP(peer) ||
		ipInRules(peer, exemptRules) || ipInRules(peer, trustedProxies)
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

// isNavigation reports whether a request is a top-level page load, the only
// kind that can be answered with a challenge page.
func isNavigation(h map[string][]string, browserUA bool) bool {
	if mode := firstHeader(h, "Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return browserUA || strings.Contains(strings.ToLower(firstHeader(h, "Accept")), "text/html")
}

func hasStaticExt(path string) bool {
	p := strings.ToLower(path)
	for _, e := range staticExtensions {
		if strings.HasSuffix(p, e) {
			return true
		}
	}
	return false
}

func rawQuery(requestURI string) string {
	if _, q, ok := strings.Cut(requestURI, "?"); ok {
		return q
	}
	return ""
}

// authHeaders mark API clients carrying their own credentials; they are never
// challenged.
var authHeaders = []string{"Authorization", "X-Api-Key", "X-Emby-Authorization", "X-Emby-Token", "X-MediaBrowser-Token", "X-Plex-Token"}
