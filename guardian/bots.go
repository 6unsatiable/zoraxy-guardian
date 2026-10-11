package guardian

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// BotProtection blocks crawlers by User-Agent and catches clients that lie
// about being a browser or a search engine. None of it needs user
// interaction, so it also covers apps and APIs.
type BotProtection struct {
	Enabled bool `json:"enabled"`
	// AI training/answer crawlers (GPTBot, ClaudeBot, CCBot, Bytespider...).
	// The list is refreshed from github.com/ai-robots-txt/ai.robots.txt.
	BlockAIScrapers bool `json:"block_ai_scrapers"`
	// SEO and marketing crawlers (Ahrefs, Semrush, MJ12...).
	BlockSEOCrawlers bool `json:"block_seo_crawlers"`
	// Headless/automation browsers (HeadlessChrome, Puppeteer, Selenium...).
	BlockHeadless bool `json:"block_headless"`
	// Block clients claiming to be Googlebot/Bingbot/... whose address
	// doesn't reverse-resolve to that search engine.
	VerifySearchEngines bool `json:"verify_search_engines"`
	// Block verified search engines too (a private homelab rarely wants to
	// be indexed). When false they bypass the browser challenge.
	BlockSearchEngines bool `json:"block_search_engines"`
	// On challenge hosts, block scripting libraries (curl, python-requests,
	// Go-http-client...) outside API paths unless they send credentials.
	BlockHTTPLibraries bool `json:"block_http_libraries"`
	// On challenge hosts, block requests whose User-Agent claims a browser
	// but which lack the headers every browser sends (Sec-Fetch-*,
	// Accept-Language).
	BlockFakeBrowsers bool `json:"block_fake_browsers"`
}

// Lowercase substrings. Kept specific: a token that could appear in a real
// browser or app User-Agent does not belong here.
var defaultAIBots = []string{
	"gptbot", "chatgpt-user", "oai-searchbot", "claudebot", "claude-web", "claude-user",
	"claude-searchbot", "anthropic-ai", "ccbot", "bytespider", "amazonbot", "perplexitybot",
	"perplexity-user", "youbot", "diffbot", "cohere-ai", "cohere-training-data-crawler",
	"meta-externalagent", "meta-externalfetcher", "facebookbot", "imagesiftbot", "omgilibot",
	"omgili", "timpibot", "ai2bot", "petalbot", "duckassistbot", "mistralai-user", "kangaroo bot",
	"webzio-extended", "iaskspider", "icc-crawler", "img2dataset", "panscient", "brightbot",
	"tiktokspider", "deepseekbot", "andibot", "crawlspace", "firecrawlagent", "quora-bot",
	"novellum", "factset_spyderbot", "sidetrade", "velenpublicwebcrawler", "scrapy",
	"applebot-extended", "google-cloudvertexbot", "gemini-deep-research", "bedrockbot",
	"semrushbot-ocob", "echobox", "linerbot", "qualifiedbot", "wardbot", "kunatocrawler",
}

var seoBots = []string{
	"ahrefsbot", "ahrefssiteaudit", "semrushbot", "siteauditbot", "mj12bot", "dotbot", "blexbot",
	"dataforseobot", "serpstatbot", "seekportbot", "barkrowler", "megaindex", "linkdexbot",
	"seokicks", "screaming frog", "rogerbot", "zoominfobot", "backlinksextendedbot", "seznambot",
	"mojeekbot", "awariobot", "awariosmartbot", "keys-so-bot", "hubspot crawler", "magpie-crawler",
	"netestate", "censysinspect", "expanse", "internet-measurement", "internetmeasurement",
	"l9explore", "l9tcpid", "leakix", "modatscanner", "odin.io", "zgrab", "fasthttp", "xfa1",
	"httpx - open-source", "custom-asynchttpclient", "visionheight", "paloaltonetworks",
}

var headlessMarkers = []string{
	"headlesschrome", "phantomjs", "puppeteer", "playwright", "selenium", "webdriver",
	"slimerjs", "htmlunit", "cypress", "splash",
}

var httpLibraries = []string{
	"python-requests", "python-urllib", "python-httpx", "aiohttp", "httpx/", "go-http-client",
	"curl/", "wget", "libwww-perl", "lwp-", "java/", "apache-httpclient", "node-fetch", "axios/",
	"undici", "got (https", "ruby", "php/", "guzzlehttp", "colly", "httrack", "mechanize",
	"okhttp-scraper", "winhttp", "powershell", "nim httpclient", "reqwest", "rust-reqwest",
}

type searchEngine struct {
	marker  string
	domains []string
}

var searchEngines = []searchEngine{
	{"googlebot", []string{".googlebot.com", ".google.com", ".googleusercontent.com"}},
	{"google-inspectiontool", []string{".googlebot.com", ".google.com"}},
	{"bingbot", []string{".search.msn.com"}},
	{"applebot", []string{".applebot.apple.com"}},
	{"yandex", []string{".yandex.ru", ".yandex.net", ".yandex.com"}},
	{"baiduspider", []string{".baidu.com", ".baidu.jp"}},
	{"duckduckbot", []string{".duckduckgo.com"}},
}

func matchAny(ua string, list []string) string {
	for _, t := range list {
		if strings.Contains(ua, t) {
			return t
		}
	}
	return ""
}

// claimedSearchEngine returns the engine a User-Agent claims to be, if any.
func claimedSearchEngine(ua string) *searchEngine {
	for i := range searchEngines {
		if strings.Contains(ua, searchEngines[i].marker) {
			return &searchEngines[i]
		}
	}
	return nil
}

// botVerifier caches forward-confirmed reverse DNS results.
type botVerifier struct {
	mu    sync.Mutex
	cache map[string]botVerdict
	// inflight holds the lookup currently running for a key, so a burst of
	// requests from one address shares a single DNS round trip.
	inflight map[string]*botCall
	// lookups are overridable in tests.
	lookupAddr func(ctx context.Context, addr string) ([]string, error)
	lookupIP   func(ctx context.Context, host string) ([]net.IPAddr, error)
}

type botCall struct {
	done chan struct{}
	ok   bool
}

type botVerdict struct {
	ok      bool
	expires time.Time
}

func newBotVerifier() *botVerifier {
	return &botVerifier{
		cache:      make(map[string]botVerdict),
		inflight:   make(map[string]*botCall),
		lookupAddr: net.DefaultResolver.LookupAddr,
		lookupIP:   net.DefaultResolver.LookupIPAddr,
	}
}

// verify reports whether ip reverse-resolves into one of the engine's
// domains and that name resolves back to ip. A DNS timeout counts as not
// verified, but is cached briefly so a flood can't stall every request.
func (v *botVerifier) verify(eng *searchEngine, ip string) bool {
	key := eng.marker + "|" + ip
	now := time.Now()
	v.mu.Lock()
	if c, ok := v.cache[key]; ok && now.Before(c.expires) {
		v.mu.Unlock()
		return c.ok
	}
	if call, ok := v.inflight[key]; ok {
		v.mu.Unlock()
		<-call.done
		return call.ok
	}
	call := &botCall{done: make(chan struct{})}
	v.inflight[key] = call
	v.mu.Unlock()

	ok := v.lookup(eng, ip)
	ttl := 6 * time.Hour
	if !ok {
		ttl = 30 * time.Minute
	}
	v.mu.Lock()
	if len(v.cache) >= maxTrackedKeys {
		for k, c := range v.cache {
			if now.After(c.expires) {
				delete(v.cache, k)
			}
		}
		// Still full: drop a tenth, not everything, so the verdicts for
		// real crawlers aren't forgotten by a flood of fake ones.
		drop := len(v.cache) - maxTrackedKeys + maxTrackedKeys/10
		for k := range v.cache {
			if drop <= 0 {
				break
			}
			delete(v.cache, k)
			drop--
		}
	}
	v.cache[key] = botVerdict{ok: ok, expires: now.Add(ttl)}
	delete(v.inflight, key)
	call.ok = ok
	close(call.done)
	v.mu.Unlock()
	return ok
}

func (v *botVerifier) lookup(eng *searchEngine, ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	names, err := v.lookupAddr(ctx, ip)
	if err != nil {
		return false
	}
	want := net.ParseIP(ip)
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		matched := false
		for _, d := range eng.domains {
			if strings.HasSuffix(name, d) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		addrs, err := v.lookupIP(ctx, name)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IP.Equal(want) {
				return true
			}
		}
	}
	return false
}

// looksLikeBrowser is true for User-Agents of the major browser engines.
func looksLikeBrowser(ua string) bool {
	return strings.HasPrefix(ua, "mozilla/") &&
		(strings.Contains(ua, "chrome/") || strings.Contains(ua, "firefox/") || strings.Contains(ua, "safari/"))
}
