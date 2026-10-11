package guardian

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ThreatFeeds blocks addresses on public blocklists of hijacked and
// criminal networks. Entries covering private, reserved or proxy ranges are
// dropped so a bad list can never lock out the LAN or Cloudflare.
type ThreatFeeds struct {
	Enabled      bool     `json:"enabled"`
	URLs         []string `json:"urls"`
	RefreshHours int      `json:"refresh_hours"`
}

var defaultFeedURLs = []string{
	"https://www.spamhaus.org/drop/drop_v4.json",
	"https://www.spamhaus.org/drop/drop_v6.json",
	"https://iplists.firehol.org/files/firehol_level1.netset",
}

const aiBotsURL = "https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json"

var reservedNets = mustCIDRs(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/127", "::ffff:0:0/96", "64:ff9b::/96", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// overlaps compares same-family networks only: net.IPNet.Contains treats
// ::ffff:0:0/96 as containing every IPv4 address.
func overlaps(a, b *net.IPNet) bool {
	if len(a.Mask) != len(b.Mask) {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// ipRange is an inclusive range of 16-byte addresses.
type ipRange struct{ lo, hi [16]byte }

// ipSet is a sorted, merged list of ranges for binary search.
type ipSet struct{ r []ipRange }

func (s *ipSet) contains(ip net.IP) bool {
	if s == nil || len(s.r) == 0 {
		return false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	var k [16]byte
	copy(k[:], ip16)
	i := sort.Search(len(s.r), func(i int) bool { return bytes.Compare(s.r[i].hi[:], k[:]) >= 0 })
	return i < len(s.r) && bytes.Compare(s.r[i].lo[:], k[:]) <= 0
}

func (s *ipSet) size() int {
	if s == nil {
		return 0
	}
	return len(s.r)
}

func buildIPSet(nets []*net.IPNet, never []*net.IPNet) *ipSet {
	var rs []ipRange
	for _, n := range nets {
		ones, total := n.Mask.Size()
		if total == 32 && ones < 8 || total == 128 && ones < 16 {
			continue // implausibly broad
		}
		skip := false
		for _, r := range reservedNets {
			if overlaps(n, r) {
				skip = true
				break
			}
		}
		for _, r := range never {
			if !skip && overlaps(n, r) {
				skip = true
			}
		}
		if skip {
			continue
		}
		var lo, hi [16]byte
		copy(lo[:], n.IP.To16())
		mask := n.Mask
		if len(mask) == 4 {
			mask = append(net.CIDRMask(96, 128)[:12:12], mask...)
		}
		for i := 0; i < 16; i++ {
			lo[i] &= mask[i]
			hi[i] = lo[i] | ^mask[i]
		}
		rs = append(rs, ipRange{lo, hi})
	}
	sort.Slice(rs, func(i, j int) bool { return bytes.Compare(rs[i].lo[:], rs[j].lo[:]) < 0 })
	merged := rs[:0]
	for _, r := range rs {
		if n := len(merged); n > 0 && bytes.Compare(r.lo[:], merged[n-1].hi[:]) <= 0 {
			if bytes.Compare(r.hi[:], merged[n-1].hi[:]) > 0 {
				merged[n-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	return &ipSet{r: merged}
}

// parseFeed accepts plain CIDR/IP lists (# or ; comments) and Spamhaus
// JSON-lines ({"cidr":"..."}).
func parseFeed(data []byte) []*net.IPNet {
	var out []*net.IPNet
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '{' {
			var v struct {
				CIDR string `json:"cidr"`
			}
			if json.Unmarshal([]byte(line), &v) != nil || v.CIDR == "" {
				continue
			}
			line = v.CIDR
		}
		if i := strings.IndexAny(line, " \t;#"); i >= 0 {
			line = line[:i]
		}
		if !strings.Contains(line, "/") {
			if ip := net.ParseIP(line); ip != nil {
				if ip.To4() != nil {
					line += "/32"
				} else {
					line += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(line); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// parseAIBots reads ai.robots.txt's robots.json: an object keyed by
// User-Agent token.
func parseAIBots(data []byte) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		k = strings.ToLower(strings.TrimSpace(k))
		// Short or generic tokens could match real browsers or apps.
		if len(k) < 5 || k == "mozilla" || strings.Contains(k, "chrome") || strings.Contains(k, "safari") {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// feedManager downloads and caches the feeds and the AI-bot list.
type feedManager struct {
	dir    string
	client *http.Client
	ips    atomic.Pointer[ipSet]
	aiBots atomic.Pointer[[]string]

	mu      sync.Mutex
	lastErr string
	updated time.Time
	kick    chan struct{}
}

func newFeedManager(dir string) *feedManager {
	f := &feedManager{
		dir:    dir,
		client: &http.Client{Timeout: 30 * time.Second},
		kick:   make(chan struct{}, 1),
	}
	list := append([]string{}, defaultAIBots...)
	f.aiBots.Store(&list)
	return f
}

func (f *feedManager) cachePath(u string) string {
	h := sha256.Sum256([]byte(u))
	return filepath.Join(f.dir, "feed-"+hex.EncodeToString(h[:6])+".txt")
}

// fetch returns the URL's content, from the disk cache when it is fresh
// (or when the download fails).
//
// count measures a payload (entries parsed). A download that parses to
// nothing, or to less than half of the cached copy, is rejected and the
// cached copy kept, so an HTML error page or truncated file can't wipe a
// good list.
func (f *feedManager) fetch(ctx context.Context, u string, maxAge time.Duration, count func([]byte) int) ([]byte, error) {
	p := f.cachePath(u)
	if st, err := os.Stat(p); err == nil && time.Since(st.ModTime()) < maxAge {
		return os.ReadFile(p)
	}
	cached, cerr := os.ReadFile(p)
	data, err := f.download(ctx, u)
	if err == nil {
		n := count(data)
		switch {
		case n == 0:
			err = &feedError{u, "download contained no usable entries"}
		case cerr == nil && n*2 < count(cached):
			err = &feedError{u, "download shrank by more than half"}
		}
	}
	if err != nil {
		if cerr == nil {
			return cached, err
		}
		return nil, err
	}
	_ = atomicWriteFile(p, data, 0o644)
	return data, nil
}

func (f *feedManager) download(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "zoraxy-guardian/1.0 (+https://github.com/6unsatiable/zoraxy-guardian)")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &feedError{u, resp.Status}
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

type feedError struct{ url, status string }

func (e *feedError) Error() string { return e.url + ": " + e.status }

// refresh rebuilds the IP set from cfg's feeds. never lists ranges that must
// not be blocked (trusted proxies, Cloudflare, exempt CIDRs).
func (f *feedManager) refresh(cfg ThreatFeeds, never []*net.IPNet) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	maxAge := time.Duration(cfg.RefreshHours) * time.Hour
	var errs []string
	if cfg.Enabled {
		var nets []*net.IPNet
		for _, u := range cfg.URLs {
			data, err := f.fetch(ctx, u, maxAge, func(b []byte) int { return len(parseFeed(b)) })
			if err != nil {
				errs = append(errs, err.Error())
			}
			nets = append(nets, parseFeed(data)...)
		}
		f.ips.Store(buildIPSet(nets, never))
	} else {
		f.ips.Store(nil)
	}
	if data, err := f.fetch(ctx, aiBotsURL, 24*time.Hour, func(b []byte) int { return len(parseAIBots(b)) }); len(data) > 0 {
		if extra := parseAIBots(data); len(extra) > 0 {
			seen := map[string]bool{}
			var list []string
			for _, t := range append(append([]string{}, defaultAIBots...), extra...) {
				if !seen[t] {
					seen[t] = true
					list = append(list, t)
				}
			}
			f.aiBots.Store(&list)
		}
	} else if err != nil {
		errs = append(errs, err.Error())
	}
	f.mu.Lock()
	f.lastErr = strings.Join(errs, "; ")
	f.updated = time.Now()
	f.mu.Unlock()
}

func (f *feedManager) trigger() {
	select {
	case f.kick <- struct{}{}:
	default:
	}
}

func (s *Store) feedLoop() {
	for {
		s.mu.RLock()
		cfg := s.cfg.ThreatFeeds
		never := s.feedNeverNets()
		s.mu.RUnlock()
		s.feeds.refresh(cfg, never)
		hours := cfg.RefreshHours
		if hours < 1 {
			hours = 12
		}
		select {
		case <-time.After(time.Duration(hours) * time.Hour):
		case <-s.feeds.kick:
		}
	}
}

// feedNeverNets must be called with s.mu held.
func (s *Store) feedNeverNets() []*net.IPNet {
	var out []*net.IPNet
	for _, rs := range [][]compiledIPRule{s.trustedProxies, s.exemptRules, cloudflareRules} {
		for _, r := range rs {
			out = append(out, r.Net)
		}
	}
	return out
}

// FeedStatus is reported by /api/status.
type FeedStatus struct {
	Ranges  int       `json:"ranges"`
	AIBots  int       `json:"ai_bots"`
	Updated time.Time `json:"updated,omitempty"`
	Error   string    `json:"error,omitempty"`
}

func (s *Store) FeedStatus() FeedStatus {
	f := s.feeds
	f.mu.Lock()
	defer f.mu.Unlock()
	return FeedStatus{Ranges: f.ips.Load().size(), AIBots: len(*f.aiBots.Load()), Updated: f.updated, Error: f.lastErr}
}
