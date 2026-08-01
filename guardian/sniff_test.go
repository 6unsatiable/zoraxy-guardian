package guardian

import (
	"os"
	"path/filepath"
	"testing"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

func newStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := LoadState(filepath.Join(dir, "config.json"), filepath.Join(dir, "log.jsonl"))
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if err := s.Update(cfg); err != nil {
		t.Fatalf("Update: %v", err)
	}
	return s
}

func req(host, ip, ua, uri string) *plugin.DynamicSniffForwardRequest {
	return &plugin.DynamicSniffForwardRequest{
		Method:     "GET",
		Host:       host,
		RemoteAddr: ip + ":1234",
		RequestURI: uri,
		URL:        uri,
		Header:     map[string][]string{"User-Agent": {ua}},
	}
}

func TestIPBlocklistIPv4AndIPv6(t *testing.T) {
	s := newStore(t, Config{
		IPBlocklist: []ScopedEntry{
			{Value: "203.0.113.0/24"},
			{Value: "2001:db8::/32"},
			{Value: "198.51.100.42"},
		},
	})
	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.5", true},
		{"203.0.114.5", false},
		{"2001:db8::dead", true},
		{"2001:db9::dead", false},
		{"198.51.100.42", true},
		{"198.51.100.43", false},
	}
	for _, tc := range cases {
		d := s.Evaluate(req("x.test", tc.ip, "ua", "/"))
		if d.Block != tc.want {
			t.Errorf("ip %s: block=%v, want %v (reason=%q)", tc.ip, d.Block, tc.want, d.Reason)
		}
	}
}

func TestIPRuleHostScope(t *testing.T) {
	s := newStore(t, Config{
		IPBlocklist: []ScopedEntry{
			{Value: "10.0.0.0/8", Hosts: []string{"*.api.test"}},
		},
	})
	if d := s.Evaluate(req("foo.api.test", "10.1.2.3", "ua", "/")); !d.Block {
		t.Errorf("expected block on scoped host, got %+v", d)
	}
	if d := s.Evaluate(req("foo.public.test", "10.1.2.3", "ua", "/")); d.Block {
		t.Errorf("expected no block on unscoped host, got %+v", d)
	}
}

func TestAllowlistEnforcementOnlyWhenScopeApplies(t *testing.T) {
	s := newStore(t, Config{
		IPAllowlist: []ScopedEntry{
			{Value: "192.168.0.0/16", Hosts: []string{"admin.test"}},
		},
	})
	// On admin.test the allowlist enforces.
	if d := s.Evaluate(req("admin.test", "10.0.0.5", "ua", "/")); !d.Block {
		t.Errorf("expected block (not-allowlisted) on scoped host")
	}
	if d := s.Evaluate(req("admin.test", "192.168.1.1", "ua", "/")); d.Block {
		t.Errorf("expected allow for matching IP on scoped host: %+v", d)
	}
	// On other hosts, no allowlist applies → no block.
	if d := s.Evaluate(req("public.test", "10.0.0.5", "ua", "/")); d.Block {
		t.Errorf("allowlist must not enforce on hosts outside its scope, got %+v", d)
	}
}

func TestUARule(t *testing.T) {
	s := newStore(t, Config{
		UABlocklist: []ScopedEntry{{Value: `(?i)sqlmap`}},
	})
	if d := s.Evaluate(req("x.test", "1.2.3.4", "sqlmap/1.0", "/")); !d.Block || d.Reason != "ua-blocklist" {
		t.Errorf("expected UA block, got %+v", d)
	}
	if d := s.Evaluate(req("x.test", "1.2.3.4", "Mozilla", "/")); d.Block {
		t.Errorf("expected no block, got %+v", d)
	}
}

func TestUARulePathExceptionDoesNotMatchQuery(t *testing.T) {
	s := newStore(t, Config{
		UABlocklist: []ScopedEntry{{Value: `(?i)sqlmap`, ExceptPaths: []string{"/robots.txt"}}},
	})
	if d := s.Evaluate(req("x.test", "1.2.3.4", "sqlmap/1.0", "/admin?next=/robots.txt")); !d.Block || d.Reason != "ua-blocklist" {
		t.Errorf("query string must not exempt a UA rule, got %+v", d)
	}
	if d := s.Evaluate(req("x.test", "1.2.3.4", "sqlmap/1.0", "/robots.txt?next=/admin")); d.Block {
		t.Errorf("path exception should still match the path, got %+v", d)
	}
}

func TestWAF(t *testing.T) {
	s := newStore(t, Config{
		WAFRules: []WAFRule{
			{Name: "sqli", Pattern: `(?i)union\s+select`, Enabled: true},
			{Name: "traversal", Pattern: `(\.\./)`, Enabled: true},
			{Name: "disabled", Pattern: `nope`, Enabled: false},
		},
	})
	if d := s.Evaluate(req("x.test", "1.2.3.4", "ua", "/?q=1 UNION SELECT")); !d.Block || d.Reason != "waf-sqli" {
		t.Errorf("expected sqli, got %+v", d)
	}
	if d := s.Evaluate(req("x.test", "1.2.3.4", "ua", "/files/../etc/passwd")); !d.Block || d.Reason != "waf-traversal" {
		t.Errorf("expected traversal, got %+v", d)
	}
	if d := s.Evaluate(req("x.test", "1.2.3.4", "ua", "/?x=nope")); d.Block {
		t.Errorf("disabled rule should not fire, got %+v", d)
	}
}

func TestHoneypotDoesNotMatchQuery(t *testing.T) {
	s := newStore(t, Config{
		Honeypot: Honeypot{Enabled: true, BanSeconds: 60, Paths: []ScopedEntry{{Value: "/.env"}}},
	})
	if d := s.Evaluate(req("x.test", "1.2.3.4", "ua", "/normal?next=/.env")); d.Block {
		t.Errorf("query string must not trigger a honeypot, got %+v", d)
	}
	if d := s.Evaluate(req("x.test", "1.2.3.4", "ua", "/.env?format=json")); !d.Block || d.Reason != "honeypot" {
		t.Errorf("honeypot should match the path, got %+v", d)
	}
}

func TestRateLimitDecision(t *testing.T) {
	s := newStore(t, Config{
		RateLimit: RateLimit{Enabled: true, RequestsPerMinute: 60, Burst: 2},
	})
	for i := 0; i < 2; i++ {
		if d := s.Evaluate(req("x.test", "1.2.3.4", "ua", "/")); d.Block {
			t.Fatalf("burst request %d unexpectedly blocked: %+v", i, d)
		}
	}
	if d := s.Evaluate(req("x.test", "1.2.3.4", "ua", "/")); !d.Block || d.Reason != "rate-limit" || d.Status != 429 {
		t.Errorf("expected rate-limit 429, got %+v", d)
	}
	// Different IP should not be affected.
	if d := s.Evaluate(req("x.test", "5.6.7.8", "ua", "/")); d.Block {
		t.Errorf("other IP should not be limited: %+v", d)
	}
}

func TestTrustedProxyUsesForwardedClientIP(t *testing.T) {
	s := newStore(t, Config{
		IPBlocklist:       []ScopedEntry{{Value: "9.9.9.9"}},
		TrustedProxyCIDRs: []string{"203.0.113.0/24"},
	})
	r := req("x.test", "203.0.113.10", "ua", "/")
	r.Header["X-Forwarded-For"] = []string{"9.9.9.9, 203.0.113.11"}
	if d := s.Evaluate(r); !d.Block || d.Reason != "ip-blocklist" {
		t.Errorf("expected forwarded client to be blocked through trusted proxy, got %+v", d)
	}

	direct := req("x.test", "198.51.100.10", "ua", "/")
	direct.Header["X-Forwarded-For"] = []string{"9.9.9.9"}
	if d := s.Evaluate(direct); d.Block {
		t.Errorf("client-supplied XFF must not be honored from an untrusted peer, got %+v", d)
	}
}

func TestMalformedForwardingHeadersFallBackToRemoteAddress(t *testing.T) {
	s := newStore(t, Config{
		IPBlocklist:       []ScopedEntry{{Value: "203.0.113.10"}},
		TrustedProxyCIDRs: []string{"203.0.113.0/24"},
	})
	r := req("x.test", "203.0.113.10", "ua", "/")
	r.Header["X-Forwarded-For"] = []string{"not-an-ip"}
	r.Header["X-Real-IP"] = []string{"also-not-an-ip"}
	if d := s.Evaluate(r); !d.Block || d.Reason != "ip-blocklist" {
		t.Errorf("malformed forwarding headers must not bypass IP rules, got %+v", d)
	}
}

func TestBlockLogPersistence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	logPath := filepath.Join(dir, "log.jsonl")
	s, err := LoadState(cfgPath, logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(Config{UABlocklist: []ScopedEntry{{Value: `(?i)sqlmap`}}}); err != nil {
		t.Fatal(err)
	}
	r := req("x.test", "1.2.3.4", "sqlmap/1.0", "/")
	d := s.Evaluate(r)
	if !d.Block {
		t.Fatal("expected sniff to block")
	}
	s.LogBlock(r, d)

	// Confirm the JSONL file has at least one line.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected blocklog file to have content")
	}

	// Reopen and verify the in-memory ring restored from disk.
	s2, err := LoadState(cfgPath, logPath)
	if err != nil {
		t.Fatal(err)
	}
	entries := s2.LogPage(0, 0)
	if len(entries) == 0 {
		t.Fatalf("expected restored log entries, got 0")
	}
	// LogPage returns newest-first.
	if entries[0].Reason != "ua-blocklist" {
		t.Errorf("last entry reason = %q, want ua-blocklist", entries[len(entries)-1].Reason)
	}
}
