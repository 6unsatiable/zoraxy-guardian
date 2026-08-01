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
