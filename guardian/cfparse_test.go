package guardian

import (
	"strings"
	"testing"
)

func TestParseCFScannerRule(t *testing.T) {
	src := `(http.request.uri.path contains "/.env") or (http.request.uri.path contains "/.git") or (http.request.uri.path contains "..") or (http.request.uri.query contains "union select") or (http.host contains "Localhost")`

	res, err := ParseCloudflareRules(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	want := map[string][]string{
		"honeypot":  {"/.env", "/.git", ".."},
		"hostblock": {"localhost"},
		"waf":       {"union select"},
	}

	hp := make([]string, 0, len(res.Honeypot))
	for _, e := range res.Honeypot {
		hp = append(hp, e.Value)
	}
	if !sliceEqual(hp, want["honeypot"]) {
		t.Errorf("honeypot = %v, want %v", hp, want["honeypot"])
	}

	if len(res.HostBlocklist) != 1 || !strings.Contains(res.HostBlocklist[0].Value, "ocalhost") {
		t.Errorf("host blocklist unexpected: %+v", res.HostBlocklist)
	}
	if len(res.WAFRules) != 1 || !strings.Contains(res.WAFRules[0].Pattern, "union select") {
		t.Errorf("waf rule unexpected: %+v", res.WAFRules)
	}
}

func TestParseCFAIBotRule(t *testing.T) {
	src := `(http.request.uri.path ne "/robots.txt") and ((http.user_agent contains "Applebot") or (http.user_agent contains "Googlebot") or (http.user_agent contains "PerplexityBot"))`

	res, err := ParseCloudflareRules(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(res.UABlocklist) != 3 {
		t.Fatalf("expected 3 UA rules, got %d: %+v", len(res.UABlocklist), res.UABlocklist)
	}
	for _, e := range res.UABlocklist {
		if len(e.ExceptPaths) != 1 || e.ExceptPaths[0] != "/robots.txt" {
			t.Errorf("UA rule missing /robots.txt except-path: %+v", e)
		}
	}

	// Verify the bot UAs are present.
	values := make([]string, 0)
	for _, e := range res.UABlocklist {
		values = append(values, e.Value)
	}
	for _, want := range []string{"Applebot", "Googlebot", "PerplexityBot"} {
		found := false
		for _, v := range values {
			if strings.Contains(v, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing UA pattern for %q in %v", want, values)
		}
	}
}

func TestParseCFMultipleRulesConcatenated(t *testing.T) {
	src := `(http.request.uri.path contains "/.env")(http.user_agent contains "Googlebot")`
	res, err := ParseCloudflareRules(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(res.Honeypot) != 1 || len(res.UABlocklist) != 1 {
		t.Errorf("expected 1 honeypot + 1 UA, got %d + %d", len(res.Honeypot), len(res.UABlocklist))
	}
}

func TestParseCFUnsupportedFieldsWarn(t *testing.T) {
	src := `(cf.threat_score gt 10) or (ip.geoip.country eq "RU")`
	res, err := ParseCloudflareRules(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(res.Warnings) < 2 {
		t.Errorf("expected warnings for cf.* and ip.geoip.*, got %v", res.Warnings)
	}
}

func TestParseCFIPSetIn(t *testing.T) {
	src := `(ip.src in {1.2.3.0/24 5.6.7.8})`
	res, err := ParseCloudflareRules(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(res.IPBlocklist) != 2 {
		t.Errorf("expected 2 IPs in blocklist, got %+v", res.IPBlocklist)
	}
}

func TestParseCFAndDoesNotBroadenRule(t *testing.T) {
	res, err := ParseCloudflareRules(`http.request.uri.path contains "/admin" and http.user_agent contains "scanner"`)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(res.Honeypot) != 0 || len(res.UABlocklist) != 0 || len(res.Warnings) == 0 {
		t.Fatalf("unsafe conjunction must be skipped with a warning, got %+v", res)
	}
}

func TestMergeSkipsDuplicates(t *testing.T) {
	cfg := Config{
		Honeypot: Honeypot{Paths: []ScopedEntry{{Value: "/.env"}}},
	}
	res := CFImportResult{
		Honeypot: []ScopedEntry{{Value: "/.env"}, {Value: "/.git"}},
	}
	stats := MergeCFResult(&cfg, res)
	if stats.Honeypot != 1 {
		t.Errorf("expected 1 added (the dup skipped), got %d", stats.Honeypot)
	}
	if len(cfg.Honeypot.Paths) != 2 {
		t.Errorf("expected 2 total, got %d", len(cfg.Honeypot.Paths))
	}
}

func TestUserExactRules(t *testing.T) {
	// The exact two rules the user shared, concatenated as in the chat.
	src := `(http.request.uri.path contains "/.env") or (http.request.uri.path contains "/.git") or (http.request.uri.path contains "/.aws") or (http.request.uri.path contains "/.config") or (http.request.uri.path contains "/.docker") or (http.request.uri.path contains "/docker-compose") or (http.request.uri.path contains "/wp-config.php") or (http.request.uri.path contains "/xmlrpc.php") or (http.request.uri.path contains "wp-content") or (http.request.uri.path contains "/phpmyadmin") or (http.request.uri.path contains "/setup.php") or (http.request.uri.path contains "/install.php") or (http.request.uri.path contains "..") or (http.request.uri.path contains "/etc/passwd") or (http.request.uri.path contains "jndi:") or (http.request.uri.path contains ".sql") or (http.request.uri.path contains ".bak") or (http.request.uri.query contains "union select") or (http.request.uri.path contains "xamp.php") or (http.host contains "Localhost")(http.request.uri.path ne "/robots.txt" and ((http.user_agent contains "Applebot") or (http.user_agent contains "archive.org_bot") or (http.user_agent contains "Arquivo-web-crawler") or (http.user_agent contains "bingbot") or (http.user_agent contains "ChatGPT-User") or (http.user_agent contains "DuckAssistBot") or (http.user_agent contains "Googlebot") or (http.user_agent contains "Manus-User") or (http.user_agent contains "meta-externalfetcher") or (http.user_agent contains "MistralAI-User") or (http.user_agent contains "OAI-SearchBot") or (http.user_agent contains "Perplexity-User") or (http.user_agent contains "PerplexityBot") or (http.user_agent contains "ProRataInc") or (http.user_agent contains "Terracotta")))`

	res, err := ParseCloudflareRules(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	// 18 path predicates → 18 honeypot entries.
	if len(res.Honeypot) != 18 {
		t.Errorf("expected 18 honeypot paths, got %d", len(res.Honeypot))
	}
	// 1 query predicate → 1 WAF.
	if len(res.WAFRules) != 1 {
		t.Errorf("expected 1 WAF rule, got %d", len(res.WAFRules))
	}
	// 1 host predicate → 1 hostblock.
	if len(res.HostBlocklist) != 1 {
		t.Errorf("expected 1 host blocklist entry, got %d", len(res.HostBlocklist))
	}
	// 15 UA predicates, all with /robots.txt except-path.
	if len(res.UABlocklist) != 15 {
		t.Errorf("expected 15 UA rules, got %d", len(res.UABlocklist))
	}
	for _, e := range res.UABlocklist {
		if len(e.ExceptPaths) != 1 || e.ExceptPaths[0] != "/robots.txt" {
			t.Errorf("UA rule missing /robots.txt except-path: %+v", e)
		}
	}
	if len(res.Warnings) > 0 {
		t.Logf("warnings (expected to be empty for these rules): %v", res.Warnings)
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
