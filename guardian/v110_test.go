package guardian

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func solveChallenge(t *testing.T, s *Store, ip string) *http.Request {
	t.Helper()
	r := req("web.test", ip, "", "/dashboard")
	r.Header = browserReq("web.test", ip, "/dashboard")
	d := s.Evaluate(r)
	m := regexp.MustCompile(`var C="([^"]+)",D=(\d+),R="([^"]*)"`).FindStringSubmatch(string(d.Body))
	if m == nil {
		t.Fatal("no challenge")
	}
	n, _ := strconv.Atoi(m[2])
	nonce := 0
	for ; ; nonce++ {
		sum := sha256.Sum256([]byte(m[1] + strconv.Itoa(nonce)))
		if leadingZeroBits(sum[:]) >= n {
			break
		}
	}
	hr, _ := http.NewRequest("GET", verifyPath+"?c="+url.QueryEscape(m[1])+"&n="+strconv.Itoa(nonce)+"&r="+m[3], nil)
	return hr
}

func TestChallengeSolutionIsOneTime(t *testing.T) {
	s := v1Store(t)
	ip := "8.8.4.4"
	hr := solveChallenge(t, s, ip)
	v := req("web.test", ip, "", hr.URL.RequestURI())
	v.Header = browserReq("", "", "")
	if d := s.Evaluate(v); d.Kind != KindRedirect {
		t.Fatalf("first use: %s", d.Reason)
	}
	if d := s.Evaluate(v); d.Reason != "challenge-failed" {
		t.Fatalf("replay accepted: %s", d.Reason)
	}
}

func TestCookieBoundToNetwork(t *testing.T) {
	cfg := v1Store(t).Snapshot()
	cfg.Challenge.BindCookieToNetwork = true
	s := newStore(t, cfg)
	hr := solveChallenge(t, s, "8.8.4.4")
	v := req("web.test", "8.8.4.4", "", hr.URL.RequestURI())
	v.Header = browserReq("", "", "")
	d := s.Evaluate(v)
	cookie := strings.SplitN(d.Headers["Set-Cookie"], ";", 2)[0]
	same := req("web.test", "8.8.4.77", "", "/dashboard")
	same.Header = browserReq("web.test", "8.8.4.77", "/dashboard")
	same.Header["Cookie"] = []string{cookie}
	if d := s.Evaluate(same); d.Block || d.Kind == KindChallenge {
		t.Fatalf("same /24 rejected: %s", d.Reason)
	}
	other := req("web.test", "9.9.9.9", "", "/dashboard")
	other.Header = browserReq("web.test", "9.9.9.9", "/dashboard")
	other.Header["Cookie"] = []string{cookie}
	if d := s.Evaluate(other); d.Kind != KindChallenge {
		t.Fatalf("cookie from another network accepted: %s", d.Reason)
	}
}

func TestConfigETagConflict(t *testing.T) {
	s := newStore(t, Config{})
	tag := s.ConfigETag()
	cfg := s.Snapshot()
	cfg.RateLimit = RateLimit{Enabled: true, RequestsPerMinute: 10, Burst: 5}
	if err := s.UpdateIfMatch(cfg, tag); err != nil {
		t.Fatal(err)
	}
	cfg.RateLimit.Burst = 6
	if err := s.UpdateIfMatch(cfg, tag); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("stale save accepted: %v", err)
	}
}

func TestBodyLimitAndHeaderWAF(t *testing.T) {
	s := newStore(t, Config{MaxBodyBytes: 1000, MaxBodyHosts: []string{"up.test"}})
	r := req("up.test", "8.8.4.4", "Mozilla/5.0", "/upload")
	r.Method = "POST"
	r.Header["Content-Length"] = []string{"5000"}
	if d := s.Evaluate(r); !d.Block || d.Reason != "body-too-large" || d.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: %+v", d)
	}
	r.Header["Content-Length"] = []string{"900"}
	r.Header["Content-Type"] = []string{"application/octet-stream"}
	if d := s.Evaluate(r); d.Block {
		t.Fatalf("small body blocked: %s", d.Reason)
	}
	o := req("other.test", "8.8.4.4", "Mozilla/5.0", "/upload")
	o.Method = "POST"
	o.Header["Content-Type"] = []string{"application/octet-stream"}
	o.Header["Content-Length"] = []string{"5000"}
	if d := s.Evaluate(o); d.Block {
		t.Fatalf("cap applied to unscoped host: %s", d.Reason)
	}
	w := newStore(t, Config{WAFRules: []WAFRule{{Name: "evil", Pattern: `evilpayload`, Enabled: true}}})
	h := req("a.test", "8.8.4.4", "Mozilla/5.0", "/")
	h.Header["X-Custom"] = []string{"evilpayload"}
	if d := w.Evaluate(h); d.Reason != "waf-evil" {
		t.Fatalf("header not scanned: %+v", d)
	}
	h2 := req("a.test", "8.8.4.4", "Mozilla/5.0", "/")
	h2.Header["Authorization"] = []string{"Bearer evilpayload"}
	if d := w.Evaluate(h2); d.Block {
		t.Fatalf("authorization scanned: %s", d.Reason)
	}
}

func TestBehaviorWindowRolls(t *testing.T) {
	b := newBehaviorTracker()
	t0 := time.Now()
	w := 60 * time.Second
	for i := 0; i < 5; i++ {
		if b.note("k", "/p"+strconv.Itoa(i), 5, w, t0.Add(time.Duration(i)*20*time.Second)) {
			t.Fatalf("banned at %d", i)
		}
	}
	// p0..p2 have rolled out by t0+130s, so two new paths stay under 5.
	if b.note("k", "/new1", 5, w, t0.Add(130*time.Second)) || b.note("k", "/new2", 5, w, t0.Add(131*time.Second)) {
		t.Fatal("old paths still counted")
	}
	// A slow crawler straddling a fixed-window boundary is still caught.
	c := newBehaviorTracker()
	hit := false
	for i := 0; i < 6; i++ {
		hit = c.note("c", "/x"+strconv.Itoa(i), 5, w, t0.Add(time.Duration(i)*10*time.Second)) || hit
	}
	if !hit {
		t.Fatal("crawler not caught")
	}
}

func TestBehaviorTrackerFullStillTracks(t *testing.T) {
	b := newBehaviorTracker()
	now := time.Now()
	for i := 0; i < maxTrackedKeys; i++ {
		b.keys["f"+strconv.Itoa(i)] = &pathWindow{seen: map[uint64]time.Time{1: now}}
	}
	b.note("newcomer", "/a", 5, time.Minute, now)
	if b.keys["newcomer"] == nil {
		t.Fatal("new key not tracked while full")
	}
	if len(b.keys) > maxTrackedKeys {
		t.Fatalf("map grew to %d", len(b.keys))
	}
}

func TestFeedRejectsBadDownloads(t *testing.T) {
	body := atomic.Value{}
	body.Store("1.2.3.0/24\n5.6.7.0/24\n8.9.10.0/24\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	f := newFeedManager(t.TempDir())
	count := func(b []byte) int { return len(parseFeed(b)) }
	ctx := context.Background()
	if d, err := f.fetch(ctx, srv.URL, 0, count); err != nil || count(d) != 3 {
		t.Fatalf("good fetch: %v", err)
	}
	for _, bad := range []string{"<html>oops</html>", "", "1.2.3.0/24\n"} {
		body.Store(bad)
		d, err := f.fetch(ctx, srv.URL, 0, count)
		if err == nil || count(d) != 3 {
			t.Fatalf("bad download %q accepted (err=%v, n=%d)", bad, err, count(d))
		}
	}
	cached, _ := f.fetch(ctx, srv.URL, time.Hour, count)
	if count(cached) != 3 {
		t.Fatal("cache overwritten")
	}
}

func TestBotVerifyCoalescesAndKeepsVerdicts(t *testing.T) {
	var calls atomic.Int32
	v := newBotVerifier()
	v.lookupAddr = func(ctx context.Context, a string) ([]string, error) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return []string{"crawl-1.googlebot.com."}, nil
	}
	v.lookupIP = func(ctx context.Context, h string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("66.249.66.1")}}, nil
	}
	eng := claimedSearchEngine("googlebot")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !v.verify(eng, "66.249.66.1") {
				t.Error("not verified")
			}
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d lookups for one address", n)
	}
	// A flood of fake entries must not evict the live verdict wholesale.
	v.mu.Lock()
	for i := 0; i < maxTrackedKeys; i++ {
		v.cache["x|"+strconv.Itoa(i)] = botVerdict{expires: time.Now().Add(time.Hour)}
	}
	v.mu.Unlock()
	v.verify(eng, "66.249.66.2")
	v.mu.Lock()
	n := len(v.cache)
	v.mu.Unlock()
	if n < maxTrackedKeys*8/10 {
		t.Fatalf("cache wiped to %d", n)
	}
}

func TestRateLimiterEvictionBounded(t *testing.T) {
	rl := newRateLimiter(60, 5)
	defer rl.Stop()
	now := time.Now()
	for i := 0; i < maxBuckets; i++ {
		rl.buckets["k"+strconv.Itoa(i)] = &bucket{tokens: 1, last: now.Add(-time.Duration(i) * time.Millisecond)}
	}
	rl.allow("fresh")
	if len(rl.buckets) > maxBuckets-maxBuckets/100+1 {
		t.Fatalf("not evicted: %d", len(rl.buckets))
	}
	if _, ok := rl.buckets["k0"]; !ok {
		t.Fatal("newest evicted instead of oldest")
	}
}

func TestBotBlocksStrike(t *testing.T) {
	cfg := v1Store(t).Snapshot()
	cfg.AutoBan = AutoBan{Enabled: true, Threshold: 3, WindowSeconds: 60, BanSeconds: 60}
	s := newStore(t, cfg)
	for i := 0; i < 3; i++ {
		s.Evaluate(req("a.test", "8.8.4.4", "Mozilla/5.0 (compatible; GPTBot/1.0)", "/"))
	}
	if d := s.Evaluate(req("a.test", "8.8.4.4", "Mozilla/5.0", "/")); d.Reason != "temp-ban" {
		t.Fatalf("scraper not banned: %s", d.Reason)
	}
}
