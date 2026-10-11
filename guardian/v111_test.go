package guardian

import (
	"strings"
	"testing"
)

func TestExpandedBotTokens(t *testing.T) {
	bad := []string{"Mozilla/5.0 (compatible; Meta-WebIndexer/1.0)", "Crawl4AI/0.4", "Mozilla/5.0 (compatible; PerplexityBot/1.0)",
		"Mozilla/5.0 (compatible; KimiBot/1.0)", "Nuclei - Open-source project", "sqlmap/1.7", "Nikto/2.5", "masscan/1.3", "Mozilla/5.0 zgrab/0.x"}
	for _, ua := range bad {
		l := strings.ToLower(ua)
		if matchAny(l, defaultAIBots) == "" && matchAny(l, seoBots) == "" {
			t.Errorf("not matched: %s", ua)
		}
	}
	good := []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 musical_ly BytedanceWebview",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15",
	}
	for _, ua := range good {
		l := strings.ToLower(ua)
		if matchAny(l, defaultAIBots) != "" || matchAny(l, seoBots) != "" {
			t.Errorf("false positive: %s", ua)
		}
	}
}
