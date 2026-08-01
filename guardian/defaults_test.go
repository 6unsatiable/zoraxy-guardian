package guardian

import "testing"

func TestRecommendedDefaultsAreConsolidatedAndValid(t *testing.T) {
	cfg := defaultConfig()

	if len(cfg.UABlocklist) != 3 {
		t.Fatalf("UA default groups = %d, want 3", len(cfg.UABlocklist))
	}
	if len(cfg.WAFRules) != 10 {
		t.Fatalf("WAF defaults = %d, want 10", len(cfg.WAFRules))
	}
	if len(cfg.Honeypot.Paths) != 20 {
		t.Fatalf("honeypot defaults = %d, want 20", len(cfg.Honeypot.Paths))
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("recommended defaults are invalid: %v", err)
	}
}

func TestMergeRecommendedRulesPreservesCustomAndScopedRules(t *testing.T) {
	cfg := Config{
		UABlocklist: []ScopedEntry{
			{Value: `(?i)sqlmap`},
			{Value: `(?i)nmap`, Hosts: []string{"admin.example"}},
			{Value: `(?i)my-private-scanner`},
		},
		WAFRules: []WAFRule{
			{Name: "xss-script", Pattern: `(?i)<script\b`, Enabled: true},
			{Name: "custom", Pattern: `(?i)private-danger`, Enabled: true},
		},
		Honeypot: Honeypot{Paths: []ScopedEntry{
			{Value: "/.git/config"},
			{Value: "/.git/HEAD", Hosts: []string{"admin.example"}},
			{Value: "/private-tripwire"},
		}},
	}

	stats := MergeRecommendedRules(&cfg)
	if stats.UARemoved != 1 || stats.WAFRemoved != 1 || stats.HoneypotRemoved != 1 {
		t.Fatalf("unexpected removal stats: %+v", stats)
	}
	if stats.UAAdded != 3 || stats.WAFAdded != 10 || stats.HoneypotAdded != 20 {
		t.Fatalf("unexpected addition stats: %+v", stats)
	}
	if len(cfg.UABlocklist) != 5 || len(cfg.WAFRules) != 11 || len(cfg.Honeypot.Paths) != 22 {
		t.Fatalf("merged rules have unexpected counts: ua=%d waf=%d honeypot=%d", len(cfg.UABlocklist), len(cfg.WAFRules), len(cfg.Honeypot.Paths))
	}
	if cfg.UABlocklist[0].Value != `(?i)nmap` || cfg.UABlocklist[1].Value != `(?i)my-private-scanner` || cfg.WAFRules[0].Name != "custom" || cfg.Honeypot.Paths[0].Value != "/.git/HEAD" {
		t.Fatalf("custom or scoped entries were changed: %+v", cfg)
	}
}
