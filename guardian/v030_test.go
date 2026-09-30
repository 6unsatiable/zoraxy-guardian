package guardian

import (
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

// cloudflareEdge is a real Cloudflare address: the one a honeypot hit banned
// in production before v0.3.0, locking out everyone behind that edge node.
const cloudflareEdge = "172.71.222.159"

func honeypotCfg() Config {
	return Config{
		Honeypot: Honeypot{Enabled: true, BanSeconds: 3600, Paths: []ScopedEntry{{Value: "/.env"}}},
		AutoBan:  AutoBan{Enabled: true, Threshold: 2, WindowSeconds: 60, BanSeconds: 600},
	}
}

func viaCloudflare(visitor, uri string) *plugin.DynamicSniffForwardRequest {
	r := req("media.example.test", cloudflareEdge, "Mozilla/5.0", uri)
	r.Header["Cf-Connecting-Ip"] = []string{visitor}
	r.Header["X-Forwarded-For"] = []string{visitor}
	return r
}

func TestTrustCloudflareBansTheVisitorNotTheEdge(t *testing.T) {
	cfg := honeypotCfg()
	cfg.TrustCloudflare = true
	s := newStore(t, cfg)

	d := s.Evaluate(viaCloudflare("198.51.100.7", "/api%2F.env"))
	if !d.Block || d.Reason != "honeypot" || d.IP != "198.51.100.7" {
		t.Fatalf("honeypot via Cloudflare: %+v", d)
	}
	if banned, _ := s.IsTempBanned("198.51.100.7"); !banned {
		t.Fatal("visitor should be temp-banned")
	}
	if banned, _ := s.IsTempBanned(cloudflareEdge); banned {
		t.Fatal("the Cloudflare edge must never be banned")
	}
	// Another visitor through the same edge is unaffected.
	if d := s.Evaluate(viaCloudflare("203.0.113.9", "/")); d.Block {
		t.Fatalf("innocent visitor blocked: %+v", d)
	}
}

func TestUntrustedCloudflareIsNeverBanned(t *testing.T) {
	s := newStore(t, honeypotCfg()) // TrustCloudflare off, as deployed before v0.3.0

	if d := s.Evaluate(viaCloudflare("198.51.100.7", "/.env")); !d.Block || d.Reason != "honeypot" {
		t.Fatalf("honeypot request should still be blocked: %+v", d)
	}
	if banned, _ := s.IsTempBanned(cloudflareEdge); banned {
		t.Fatal("proxy address was temp-banned")
	}
	// No strikes either: three WAF hits must not auto-ban the edge.
	for i := 0; i < 3; i++ {
		s.Evaluate(viaCloudflare("198.51.100.7", "/?q=union%20select"))
	}
	if d := s.Evaluate(viaCloudflare("203.0.113.9", "/")); d.Block {
		t.Fatalf("everyone behind the edge got blocked: %+v", d)
	}
	if w := s.ProxyWarningSnapshot(); w.Count == 0 || w.LastIP != cloudflareEdge {
		t.Fatalf("proxy warning not recorded: %+v", w)
	}
}

func TestUntrustedCloudflareIsNotRateLimited(t *testing.T) {
	s := newStore(t, Config{RateLimit: RateLimit{Enabled: true, RequestsPerMinute: 1, Burst: 1}})
	for i := 0; i < 5; i++ {
		if d := s.Evaluate(viaCloudflare("198.51.100.7", "/")); d.Block {
			t.Fatalf("request %d through an untrusted proxy was rate limited", i)
		}
	}
}

func TestCFConnectingIPOnlyFromCloudflare(t *testing.T) {
	trusted := compileIPRules(scopedEntries([]string{"10.0.0.0/8"}))
	r := req("x.test", "10.0.0.1", "ua", "/")
	r.Header["Cf-Connecting-Ip"] = []string{"1.2.3.4"} // forged by the client, passed on by a local proxy
	r.Header["X-Forwarded-For"] = []string{"5.6.7.8"}
	if got := clientIP(r, trusted); got != "5.6.7.8" {
		t.Fatalf("clientIP = %s, want 5.6.7.8 (CF-Connecting-IP must be ignored from non-Cloudflare peers)", got)
	}
}

func TestXForwardedForAcrossHeaderLines(t *testing.T) {
	trusted := compileIPRules(scopedEntries([]string{"10.0.0.0/8"}))
	r := req("x.test", "10.0.0.1", "ua", "/")
	// A client-supplied first line, then the line the trusted proxy appended.
	r.Header["X-Forwarded-For"] = []string{"1.1.1.1", "2.2.2.2"}
	if got := clientIP(r, trusted); got != "2.2.2.2" {
		t.Fatalf("clientIP = %s, want 2.2.2.2", got)
	}
}

func TestZoraxyResolvedClientIP(t *testing.T) {
	r := req("x.test", "192.0.2.10", "ua", "/")
	r.ClientIP = "198.51.100.20" // Zoraxy resolved this through its own trusted proxies
	if got := clientIP(r, nil); got != "198.51.100.20" {
		t.Fatalf("clientIP = %s, want Zoraxy's client_ip", got)
	}
	r.ClientIP = "192.0.2.10" // Zoraxy didn't trust headers: same as the peer
	r.Header["X-Forwarded-For"] = []string{"6.6.6.6"}
	if got := clientIP(r, nil); got != "192.0.2.10" {
		t.Fatalf("clientIP = %s, want the peer", got)
	}
}

func TestIPv6BansCoverTheSlash64(t *testing.T) {
	s := newStore(t, honeypotCfg())
	if d := s.Evaluate(req("x.test", "2001:db8:1:2::5", "ua", "/.env")); d.Reason != "honeypot" {
		t.Fatalf("honeypot not hit: %+v", d)
	}
	if d := s.Evaluate(req("x.test", "2001:db8:1:2:abcd::99", "ua", "/")); d.Reason != "temp-ban" {
		t.Fatalf("same /64 should be banned: %+v", d)
	}
	if d := s.Evaluate(req("x.test", "2001:db8:1:3::1", "ua", "/")); d.Block {
		t.Fatalf("neighbouring /64 should not be banned: %+v", d)
	}
	s.ClearTempBan("2001:db8:1:2::7")
	if d := s.Evaluate(req("x.test", "2001:db8:1:2::5", "ua", "/")); d.Block {
		t.Fatalf("clearing by address should lift the /64 ban: %+v", d)
	}
}

func TestHoneypotMatching(t *testing.T) {
	s := newStore(t, Config{Honeypot: Honeypot{Enabled: true, BanSeconds: 60, Paths: []ScopedEntry{
		{Value: "/.env"}, {Value: "/backup*.zip"}, {Value: "/**/phpinfo.php"},
	}}})
	cases := []struct {
		uri  string
		want bool
	}{
		{"/.ENV", true},              // case-insensitive
		{"/api/.env", true},          // literal matches anywhere
		{"/?file=/.env", false},      // query strings don't count
		{"/backup.2024.zip", true},   // '*' may contain dots
		{"/backup/x.zip", false},     // but not slashes
		{"/a/b/phpinfo.php", true},   // '**' spans segments
		{"/phpinfo.php.bak", false},  // globs match the whole path
		{"/wp-content/x.png", false}, // unrelated
	}
	for i, tc := range cases {
		ip := "192.0.2." + string(rune('1'+i)) // fresh IP so earlier bans don't interfere
		d := s.Evaluate(req("x.test", ip, "ua", tc.uri))
		if (d.Reason == "honeypot") != tc.want {
			t.Errorf("%s: reason=%q, want honeypot=%v", tc.uri, d.Reason, tc.want)
		}
	}
}

func TestWAFSeesDecodedPayloads(t *testing.T) {
	s := newStore(t, Config{})
	for _, uri := range []string{
		"/?q=%3Cscript%3Ealert(1)%3C/script%3E",
		"/static/..%2f..%2fetc/passwd",
		"/?q=%253Cscript%253E", // double-encoded
		"/?q=%zz%3Cscript%3E",  // a malformed escape doesn't hide the rest
	} {
		if d := s.Evaluate(req("x.test", "192.0.2.50", "ua", uri)); !d.Block || !strings.HasPrefix(d.Reason, "waf-") {
			t.Errorf("%s not caught: %+v", uri, d)
		}
	}
	if d := s.Evaluate(req("x.test", "192.0.2.51", "ua", "/search?q=100%25%20cotton")); d.Block {
		t.Errorf("benign encoded query blocked: %+v", d)
	}
}

func TestCSVExportNeutralizesFormulas(t *testing.T) {
	for in, want := range map[string]string{
		"=HYPERLINK(\"http://x\")": "'=HYPERLINK(\"http://x\")",
		"+1":                       "'+1",
		"@SUM(A1)":                 "'@SUM(A1)",
		"Mozilla/5.0":              "Mozilla/5.0",
		"":                         "",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBansSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	cfgPath, logPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "log.jsonl")
	s, err := LoadState(cfgPath, logPath)
	if err != nil {
		t.Fatal(err)
	}
	s.AddTempBan("198.51.100.7", time.Hour)
	s.AddFingerprintBan("abc123", time.Hour)
	if err := s.SaveBans(); err != nil {
		t.Fatal(err)
	}
	s2, err := LoadState(cfgPath, logPath)
	if err != nil {
		t.Fatal(err)
	}
	if banned, _ := s2.IsTempBanned("198.51.100.7"); !banned {
		t.Fatal("temp ban lost on restart")
	}
	if banned, _ := s2.IsFingerprintBanned("abc123"); !banned {
		t.Fatal("fingerprint ban lost on restart")
	}
}

func TestValidationErrorsAreBadRequests(t *testing.T) {
	s := newStore(t, Config{})
	err := s.Update(Config{UABlocklist: []ScopedEntry{{Value: "(unclosed"}}})
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	rec := httptest.NewRecorder()
	writeUpdateError(rec, err)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "UA blocklist entry 1") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestRepeatTempBanHitsAreThrottledInTheLog(t *testing.T) {
	s := newStore(t, honeypotCfg())
	for _, uri := range []string{"/.env", "/", "/a", "/b"} {
		r := req("x.test", "198.51.100.7", "ua", uri)
		if d := s.Evaluate(r); d.Block {
			s.LogBlock(r, d)
		}
	}
	summary := s.BlockLogSummary(10)
	counts := map[string]int{}
	for _, c := range summary.TopReasons {
		counts[c.Value] = c.Count
	}
	if counts["honeypot"] != 1 || counts["temp-ban"] != 1 {
		t.Fatalf("log counts %v, want one honeypot and one temp-ban entry", counts)
	}
	if s.SuppressedRepeats() != 2 {
		t.Fatalf("suppressed = %d, want 2", s.SuppressedRepeats())
	}
}

func TestLogSourceFilterAndZoraxyMirrorToggle(t *testing.T) {
	s := newStore(t, Config{})
	s.LogEntry(BlockLogEntry{Source: "guardian", Reason: "waf-x", IP: "1.1.1.1"})
	s.LogEntry(BlockLogEntry{Source: "zoraxy", Reason: "zoraxy-blacklist", IP: "2.2.2.2"})
	if n := s.LogTotalSource("guardian"); n != 1 {
		t.Fatalf("guardian entries = %d", n)
	}
	if got := s.LogPageSource("zoraxy", 0, 0); len(got) != 1 || got[0].IP != "2.2.2.2" {
		t.Fatalf("zoraxy page = %+v", got)
	}
	if err := s.Update(Config{IgnoreZoraxyBlacklist: true}); err != nil {
		t.Fatal(err)
	}
	s.LogEntry(BlockLogEntry{Source: "zoraxy", Reason: "zoraxy-blacklist", IP: "3.3.3.3"})
	if n := s.LogTotalSource("zoraxy"); n != 1 {
		t.Fatalf("zoraxy entries = %d after disabling the mirror", n)
	}
}

func TestStrikeTrackingIsBounded(t *testing.T) {
	s := newStore(t, Config{AutoBan: AutoBan{Enabled: true, Threshold: 3, WindowSeconds: 60, BanSeconds: 60}})
	for i := 0; i < maxTrackedKeys+500; i++ {
		s.RecordStrike("k" + string(rune(i)))
	}
	s.banMu.Lock()
	n := len(s.strikes)
	s.banMu.Unlock()
	if n > maxTrackedKeys {
		t.Fatalf("strike map grew to %d (cap %d)", n, maxTrackedKeys)
	}
}
