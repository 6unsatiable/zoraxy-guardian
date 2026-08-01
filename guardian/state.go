package guardian

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

// ScopedEntry pairs a rule value (IP/CIDR or regex) with an optional set of
// host glob patterns. An empty Hosts slice means the entry applies to all
// hosts proxied through this plugin.
//
// ExceptPaths is only honored for UA blocklist entries: if the request path
// substring-matches any entry in ExceptPaths the UA rule is skipped (e.g.
// allow /robots.txt even when blocking a bot's UA).
type ScopedEntry struct {
	Value       string   `json:"value"`
	Hosts       []string `json:"hosts,omitempty"`
	ExceptPaths []string `json:"except_paths,omitempty"`
}

type Config struct {
	IPAllowlist         []ScopedEntry       `json:"ip_allowlist"`
	IPBlocklist         []ScopedEntry       `json:"ip_blocklist"`
	UABlocklist         []ScopedEntry       `json:"ua_blocklist"`
	HostBlocklist       []ScopedEntry       `json:"host_blocklist"`
	WAFRules            []WAFRule           `json:"waf_rules"`
	RateLimit           RateLimit           `json:"rate_limit"`
	Honeypot            Honeypot            `json:"honeypot"`
	AutoBan             AutoBan             `json:"auto_ban"`
	FingerprintTracking FingerprintTracking `json:"fingerprint_tracking"`
	TrustXFF            bool                `json:"trust_xff"`
}

type WAFRule struct {
	Name    string   `json:"name"`
	Pattern string   `json:"pattern"`
	Enabled bool     `json:"enabled"`
	Hosts   []string `json:"hosts,omitempty"`
}

type RateLimit struct {
	Enabled           bool `json:"enabled"`
	RequestsPerMinute int  `json:"requests_per_minute"`
	Burst             int  `json:"burst"`
}

// Honeypot fires before any other rule: any request whose path matches one
// of the configured glob patterns gets the source IP added to TempBans for
// BanSeconds. The IP stays blocked even on unrelated paths until the ban
// expires.
type Honeypot struct {
	Enabled    bool          `json:"enabled"`
	Paths      []ScopedEntry `json:"paths"`
	BanSeconds int           `json:"ban_seconds"`
}

// AutoBan tracks how many times an IP has tripped Guardian's rules in a
// rolling window; if it crosses Threshold in WindowSeconds the IP is added
// to TempBans for BanSeconds.
type AutoBan struct {
	Enabled       bool `json:"enabled"`
	Threshold     int  `json:"threshold"`
	WindowSeconds int  `json:"window_seconds"`
	BanSeconds    int  `json:"ban_seconds"`
}

// FingerprintTracking enables tracking and banning request signatures across
// IP changes. Useful for detecting persistent malicious actors using the same
// tooling/headers but rotating IPs.
type FingerprintTracking struct {
	Enabled       bool `json:"enabled"`
	Threshold     int  `json:"threshold"`      // Strikes before signature ban
	WindowSeconds int  `json:"window_seconds"` // Rolling window for strikes
	BanSeconds    int  `json:"ban_seconds"`    // How long to ban the signature
}

type BlockLogEntry struct {
	Time        time.Time `json:"time"`
	Source      string    `json:"source"` // "guardian" or "zoraxy"
	IP          string    `json:"ip"`
	Fingerprint string    `json:"fingerprint,omitempty"` // Request signature hash
	Host        string    `json:"host"`
	Method      string    `json:"method"`
	RequestURI  string    `json:"request_uri"`
	UserAgent   string    `json:"user_agent"`
	Reason      string    `json:"reason"`
	Status      int       `json:"status"`
}

type compiledIPRule struct {
	Net   *net.IPNet
	Hosts []string
}

type compiledRegexRule struct {
	RE    *regexp.Regexp
	Hosts []string
}

// compiledGlobRule is used for honeypot path matching.
type compiledGlobRule struct {
	RE    *regexp.Regexp
	Hosts []string
}

// compiledUARule extends a regex rule with optional ExceptPaths: literal
// substring path tokens that exempt a request from this rule.
type compiledUARule struct {
	RE          *regexp.Regexp
	Hosts       []string
	ExceptPaths []string
}

type Store struct {
	configPath string
	logPath    string

	mu             sync.RWMutex
	configMu       sync.Mutex
	cfg            Config
	allowRules     []compiledIPRule
	blockRules     []compiledIPRule
	uaRules        []compiledUARule
	hostBlockRules []compiledRegexRule
	wafRules       []compiledRegexRule
	wafRuleNames   []string
	honeypotRules  []compiledGlobRule
	limiter        *rateLimiter
	log            *blockLog
	bcast          *broadcaster

	pendingMu sync.Mutex
	pending   map[string]pendingDecision

	// Temporary bans + strike tracking (separate mutex; hot path).
	banMu              sync.Mutex
	tempBans           map[string]time.Time   // IP -> expiry
	strikes            map[string][]time.Time // IP -> recent strike timestamps
	fingerprintBans    map[string]time.Time   // Fingerprint -> expiry
	fingerprintStrikes map[string][]time.Time // Fingerprint -> strike timestamps
}

const (
	maxPendingDecisions = 10000
	pendingDecisionTTL  = 2 * time.Minute
)

type pendingDecision struct {
	decision Decision
	created  time.Time
}

type Decision struct {
	Block  bool
	Reason string
	Status int
}

func LoadState(configPath, logPath string) (*Store, error) {
	s := &Store{
		configPath:         configPath,
		logPath:            logPath,
		pending:            make(map[string]pendingDecision),
		tempBans:           make(map[string]time.Time),
		strikes:            make(map[string][]time.Time),
		fingerprintBans:    make(map[string]time.Time),
		fingerprintStrikes: make(map[string][]time.Time),
		bcast:              newBroadcaster(),
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		s.cfg = defaultConfig()
	} else {
		if err := json.Unmarshal(data, &s.cfg); err != nil {
			return nil, err
		}
		// Backfill defaults for fields that may be missing from older
		// config files (Honeypot/AutoBan didn't exist before v0.3).
		s.cfg = mergeDefaults(s.cfg)
	}
	s.compile()
	log, err := openBlockLog(logPath, maxBlockLog)
	if err != nil {
		return nil, err
	}
	s.log = log
	go s.banSweepLoop()
	return s, nil
}

func defaultConfig() Config {
	return mergeDefaults(Config{})
}

// mergeDefaults fills zero-value fields with sensible defaults. Used both
// for fresh installs and to upgrade old config files in place.
func mergeDefaults(c Config) Config {
	if c.IPAllowlist == nil {
		c.IPAllowlist = []ScopedEntry{}
	}
	if c.IPBlocklist == nil {
		c.IPBlocklist = []ScopedEntry{}
	}
	if c.HostBlocklist == nil {
		c.HostBlocklist = []ScopedEntry{}
	}
	if c.UABlocklist == nil {
		c.UABlocklist = []ScopedEntry{
			// Keep scanner signatures grouped by purpose so the default policy
			// is easier to review without sacrificing coverage.
			{Value: `(?i)\b(nmap|masscan|zmap|zgrab|unicornscan)\b`},
			{Value: `(?i)\b(sqlmap|nikto|acunetix|nessus|openvas|w3af|arachni|wapiti|nuclei)\b`},
			{Value: `(?i)\b(dirbuster|gobuster|feroxbuster|ffuf|dirb|wfuzz|whatweb)\b`},
		}
	}
	if c.WAFRules == nil {
		c.WAFRules = []WAFRule{
			{Name: "sqli-union", Pattern: `(?i)union[\s/*]+select`, Enabled: true},
			{Name: "sqli-boolean-comment", Pattern: `(?i)(--|#|/\*).*(\bor\b|\band\b)`, Enabled: true},
			{Name: "sqli-time-based", Pattern: `(?i)\b(sleep|benchmark|pg_sleep)\s*\(`, Enabled: true},
			{Name: "xss-pattern", Pattern: `(?i)(<script\b|javascript:|\bon\w+\s*=)`, Enabled: true},
			{Name: "path-traversal", Pattern: `(\.\./|\.\.\\)`, Enabled: true},
			{Name: "null-byte", Pattern: `(?i)%00`, Enabled: true},
			{Name: "command-injection", Pattern: `(?i)(;|\|\||&&|%0a|%0d)(\s|%20)*(curl|wget|bash|sh|cmd|powershell|nc|netcat)\b`, Enabled: true},
			{Name: "log4shell", Pattern: `(?i)\$\{jndi:[^}]+\}`, Enabled: true},
			{Name: "dangerous-uri-scheme", Pattern: `(?i)(php|file|expect)://`, Enabled: true},
			{Name: "ssrf-metadata", Pattern: `(?i)(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254)`, Enabled: true},
		}
	}
	if c.RateLimit.RequestsPerMinute == 0 {
		c.RateLimit.RequestsPerMinute = 120
	}
	if c.RateLimit.Burst == 0 {
		c.RateLimit.Burst = 30
	}
	if c.Honeypot.Paths == nil {
		c.Honeypot.Paths = []ScopedEntry{
			{Value: "/.env"},
			{Value: "/.git/"},
			{Value: "/.aws/"},
			{Value: "/.ssh/"},
			{Value: "/.docker/config.json"},
			{Value: "/.kube/config"},
			{Value: "/.npmrc"},
			{Value: "/wp-login.php"},
			{Value: "/wp-admin/setup-config.php"},
			{Value: "/phpmyadmin/"},
			{Value: "/adminer.php"},
			{Value: "/admin/config.php"},
			{Value: "/vendor/phpunit/"},
			{Value: "/actuator/env"},
			{Value: "/actuator/heapdump"},
			{Value: "/solr/admin/"},
			{Value: "/manager/html"},
			{Value: "/HNAP1/"},
			{Value: "/boaform/"},
			{Value: "/cgi-bin/"},
		}
	}
	if c.Honeypot.BanSeconds == 0 {
		c.Honeypot.BanSeconds = 3600
	}
	if c.AutoBan.Threshold == 0 {
		c.AutoBan.Threshold = 5
	}
	if c.AutoBan.WindowSeconds == 0 {
		c.AutoBan.WindowSeconds = 60
	}
	if c.AutoBan.BanSeconds == 0 {
		c.AutoBan.BanSeconds = 600
	}
	// Fingerprint tracking defaults
	if c.FingerprintTracking.Threshold == 0 {
		c.FingerprintTracking.Threshold = 10 // Higher than IP auto-ban
	}
	if c.FingerprintTracking.WindowSeconds == 0 {
		c.FingerprintTracking.WindowSeconds = 300 // 5 min window
	}
	if c.FingerprintTracking.BanSeconds == 0 {
		c.FingerprintTracking.BanSeconds = 3600 // 1 hour ban
	}
	return c
}

func (s *Store) compile() {
	// Stop the old limiter goroutine before swapping in a new one.
	if s.limiter != nil {
		s.limiter.Stop()
		s.limiter = nil
	}

	s.allowRules = compileIPRules(s.cfg.IPAllowlist)
	s.blockRules = compileIPRules(s.cfg.IPBlocklist)
	s.uaRules = compileUARules(s.cfg.UABlocklist)
	s.hostBlockRules = compileRegexRules(s.cfg.HostBlocklist)

	s.wafRules = make([]compiledRegexRule, 0, len(s.cfg.WAFRules))
	s.wafRuleNames = make([]string, 0, len(s.cfg.WAFRules))
	for _, r := range s.cfg.WAFRules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		s.wafRules = append(s.wafRules, compiledRegexRule{RE: re, Hosts: r.Hosts})
		s.wafRuleNames = append(s.wafRuleNames, r.Name)
	}

	s.honeypotRules = nil
	if s.cfg.Honeypot.Enabled {
		s.honeypotRules = compileGlobRules(s.cfg.Honeypot.Paths)
	}

	if s.cfg.RateLimit.Enabled {
		s.limiter = newRateLimiter(s.cfg.RateLimit.RequestsPerMinute, s.cfg.RateLimit.Burst)
	}
}

func compileIPRules(entries []ScopedEntry) []compiledIPRule {
	out := make([]compiledIPRule, 0, len(entries))
	for _, e := range entries {
		var ipnet *net.IPNet
		if _, n, err := net.ParseCIDR(e.Value); err == nil {
			ipnet = n
		} else if ip := net.ParseIP(e.Value); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		} else {
			continue
		}
		out = append(out, compiledIPRule{Net: ipnet, Hosts: e.Hosts})
	}
	return out
}

func compileRegexRules(entries []ScopedEntry) []compiledRegexRule {
	out := make([]compiledRegexRule, 0, len(entries))
	for _, e := range entries {
		re, err := regexp.Compile(e.Value)
		if err != nil {
			continue
		}
		out = append(out, compiledRegexRule{RE: re, Hosts: e.Hosts})
	}
	return out
}

func compileUARules(entries []ScopedEntry) []compiledUARule {
	out := make([]compiledUARule, 0, len(entries))
	for _, e := range entries {
		re, err := regexp.Compile(e.Value)
		if err != nil {
			continue
		}
		out = append(out, compiledUARule{RE: re, Hosts: e.Hosts, ExceptPaths: e.ExceptPaths})
	}
	return out
}

// compileGlobRules accepts path patterns: either a literal prefix (matches
// anywhere in the request URI) or a path containing `*` which is converted
// to regex (where `*` matches anything except `/`).
func compileGlobRules(entries []ScopedEntry) []compiledGlobRule {
	out := make([]compiledGlobRule, 0, len(entries))
	for _, e := range entries {
		val := e.Value
		if val == "" {
			continue
		}
		var re *regexp.Regexp
		var err error
		if !regexp.MustCompile(`[*?]`).MatchString(val) {
			// Plain prefix: match anywhere in the URI as a literal.
			re = regexp.MustCompile(regexp.QuoteMeta(val))
		} else {
			re, err = regexp.Compile(globToRegex(val))
			if err != nil {
				continue
			}
		}
		out = append(out, compiledGlobRule{RE: re, Hosts: e.Hosts})
	}
	return out
}

func (s *Store) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.cfg
	cfg.IPAllowlist = append([]ScopedEntry{}, s.cfg.IPAllowlist...)
	cfg.IPBlocklist = append([]ScopedEntry{}, s.cfg.IPBlocklist...)
	cfg.UABlocklist = append([]ScopedEntry{}, s.cfg.UABlocklist...)
	cfg.HostBlocklist = append([]ScopedEntry{}, s.cfg.HostBlocklist...)
	cfg.WAFRules = append([]WAFRule{}, s.cfg.WAFRules...)
	cfg.Honeypot.Paths = append([]ScopedEntry{}, s.cfg.Honeypot.Paths...)
	return cfg
}

func (s *Store) Update(cfg Config) error {
	cfg = mergeDefaults(cfg)
	if err := validateConfig(cfg); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	// Persist before publishing the new configuration. This keeps the
	// running policy and config.json consistent if the filesystem is full or
	// otherwise unavailable.
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := atomicWriteFile(s.configPath, data, 0o644); err != nil {
		return err
	}
	s.cfg = cfg
	s.compile()
	return nil
}

// validateConfig prevents a successful save from silently producing rules
// that compile to no-op (or match everything because their value is empty).
func validateConfig(cfg Config) error {
	if err := validateIPEntries("IP allowlist", cfg.IPAllowlist); err != nil {
		return err
	}
	if err := validateIPEntries("IP blocklist", cfg.IPBlocklist); err != nil {
		return err
	}
	if err := validateRegexEntries("UA blocklist", cfg.UABlocklist); err != nil {
		return err
	}
	if err := validateRegexEntries("host blocklist", cfg.HostBlocklist); err != nil {
		return err
	}
	for i, r := range cfg.WAFRules {
		if r.Name == "" || r.Pattern == "" {
			return fmt.Errorf("WAF rule %d must have a name and pattern", i+1)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("WAF rule %d: %w", i+1, err)
		}
	}
	if cfg.RateLimit.Enabled && (cfg.RateLimit.RequestsPerMinute < 1 || cfg.RateLimit.Burst < 1) {
		return fmt.Errorf("rate limit requests per minute and burst must be positive")
	}
	if cfg.Honeypot.Enabled && cfg.Honeypot.BanSeconds < 1 {
		return fmt.Errorf("honeypot ban duration must be positive")
	}
	if cfg.AutoBan.Enabled && (cfg.AutoBan.Threshold < 1 || cfg.AutoBan.WindowSeconds < 1 || cfg.AutoBan.BanSeconds < 1) {
		return fmt.Errorf("auto-ban threshold, window, and duration must be positive")
	}
	if cfg.FingerprintTracking.Enabled && (cfg.FingerprintTracking.Threshold < 1 || cfg.FingerprintTracking.WindowSeconds < 1 || cfg.FingerprintTracking.BanSeconds < 1) {
		return fmt.Errorf("fingerprint threshold, window, and duration must be positive")
	}
	return nil
}

func validateIPEntries(name string, entries []ScopedEntry) error {
	for i, entry := range entries {
		if _, _, err := net.ParseCIDR(entry.Value); err == nil {
			continue
		}
		if net.ParseIP(entry.Value) == nil {
			return fmt.Errorf("%s entry %d is not a valid IP address or CIDR", name, i+1)
		}
	}
	return nil
}

func validateRegexEntries(name string, entries []ScopedEntry) error {
	for i, entry := range entries {
		if entry.Value == "" {
			return fmt.Errorf("%s entry %d must not be empty", name, i+1)
		}
		if _, err := regexp.Compile(entry.Value); err != nil {
			return fmt.Errorf("%s entry %d: %w", name, i+1, err)
		}
	}
	return nil
}

// Save writes config.json atomically via tmp + rename. Survives a crash
// mid-write: either the new file is in place or the old one is.
func (s *Store) Save() error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.mu.RLock()
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	return atomicWriteFile(s.configPath, data, 0o644)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func (s *Store) RecordDecision(uuid string, d Decision) {
	if uuid == "" {
		return
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	now := time.Now()
	for id, pending := range s.pending {
		if now.Sub(pending.created) > pendingDecisionTTL {
			delete(s.pending, id)
		}
	}
	if len(s.pending) >= maxPendingDecisions {
		return
	}
	s.pending[uuid] = pendingDecision{decision: d, created: now}
}

func (s *Store) TakeDecision(uuid string) (Decision, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	pending, ok := s.pending[uuid]
	if ok {
		delete(s.pending, uuid)
	}
	if !ok || time.Since(pending.created) > pendingDecisionTTL {
		return Decision{}, false
	}
	return pending.decision, true
}

func (s *Store) LogBlock(req *plugin.DynamicSniffForwardRequest, d Decision) {
	s.mu.RLock()
	trust := s.cfg.TrustXFF
	fpEnabled := s.cfg.FingerprintTracking.Enabled
	s.mu.RUnlock()

	entry := BlockLogEntry{
		Time:       time.Now().UTC(),
		Source:     "guardian",
		IP:         clientIP(req, trust),
		Host:       req.Host,
		Method:     req.Method,
		RequestURI: req.RequestURI,
		UserAgent:  firstHeader(req.Header, "User-Agent"),
		Reason:     d.Reason,
		Status:     d.Status,
	}

	// Add fingerprint if tracking is enabled
	if fpEnabled {
		entry.Fingerprint = GenerateFingerprint(req)
	}

	s.log.Append(entry)
	s.bcast.publish(entry)
}

func (s *Store) LogEntry(entry BlockLogEntry) {
	if entry.Time.IsZero() {
		entry.Time = time.Now().UTC()
	}
	s.log.Append(entry)
	s.bcast.publish(entry)
}

// LogPage returns blocklog entries newest-first, paginated.
func (s *Store) LogPage(offset, limit int) []BlockLogEntry {
	all := s.log.Snapshot()
	// Reverse: ring is oldest-first; UI wants newest-first.
	n := len(all)
	rev := make([]BlockLogEntry, n)
	for i, e := range all {
		rev[n-1-i] = e
	}
	// Offset and limit are ultimately supplied through query parameters.
	// Clamp negatives before slicing so malformed requests cannot panic the
	// plugin process. A zero limit retains the documented "all entries"
	// behavior.
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}
	if offset >= n {
		return []BlockLogEntry{}
	}
	remaining := n - offset
	// Compare limit to the remaining entries before adding it to offset so a
	// crafted, very large query value cannot overflow int and panic.
	if limit <= 0 || limit >= remaining {
		return rev[offset:]
	}
	end := offset + limit
	if end > n {
		end = n
	}
	return rev[offset:end]
}

func (s *Store) LogTotal() int {
	return len(s.log.Snapshot())
}

// Broadcaster returns the underlying log broadcaster for SSE subscribers.
func (s *Store) Broadcaster() *broadcaster { return s.bcast }

// --- temp bans / strike tracking ---

// IsTempBanned returns true if the IP currently has an active temp ban.
// Lazily purges expired entries on each call.
func (s *Store) IsTempBanned(ip string) (bool, time.Time) {
	if ip == "" {
		return false, time.Time{}
	}
	s.banMu.Lock()
	defer s.banMu.Unlock()
	exp, ok := s.tempBans[ip]
	if !ok {
		return false, time.Time{}
	}
	if time.Now().After(exp) {
		delete(s.tempBans, ip)
		return false, time.Time{}
	}
	return true, exp
}

// AddTempBan installs or extends a temp ban on ip for the given duration.
func (s *Store) AddTempBan(ip string, dur time.Duration) {
	if ip == "" || dur <= 0 {
		return
	}
	expiry := time.Now().Add(dur)
	s.banMu.Lock()
	if cur, ok := s.tempBans[ip]; !ok || cur.Before(expiry) {
		s.tempBans[ip] = expiry
	}
	s.banMu.Unlock()
}

// RecordStrike adds a block strike for ip. If the count of strikes within
// the configured window crosses Threshold, the IP is added to TempBans and
// the function returns the resulting ban duration (zero if none).
func (s *Store) RecordStrike(ip string) time.Duration {
	if ip == "" {
		return 0
	}
	s.mu.RLock()
	cfg := s.cfg.AutoBan
	s.mu.RUnlock()
	if !cfg.Enabled || cfg.Threshold < 1 {
		return 0
	}
	now := time.Now()
	cutoff := now.Add(-time.Duration(cfg.WindowSeconds) * time.Second)

	s.banMu.Lock()
	hist := s.strikes[ip]
	// Drop strikes outside the window.
	keep := hist[:0]
	for _, t := range hist {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	s.strikes[ip] = keep
	count := len(keep)
	s.banMu.Unlock()

	if count >= cfg.Threshold {
		dur := time.Duration(cfg.BanSeconds) * time.Second
		s.AddTempBan(ip, dur)
		// Reset strikes once promoted so re-bans require fresh activity.
		s.banMu.Lock()
		delete(s.strikes, ip)
		s.banMu.Unlock()
		return dur
	}
	return 0
}

// TempBansSnapshot returns a copy of the current temp-ban map.
func (s *Store) TempBansSnapshot() map[string]time.Time {
	s.banMu.Lock()
	defer s.banMu.Unlock()
	now := time.Now()
	out := make(map[string]time.Time, len(s.tempBans))
	for k, v := range s.tempBans {
		if v.After(now) {
			out[k] = v
		}
	}
	return out
}

// ClearTempBan removes an active temp ban.
func (s *Store) ClearTempBan(ip string) {
	s.banMu.Lock()
	delete(s.tempBans, ip)
	delete(s.strikes, ip)
	s.banMu.Unlock()
}

// banSweepLoop periodically removes expired temp bans and old strike
// records. Cheap; only runs once a minute.
func (s *Store) banSweepLoop() {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		s.banMu.Lock()
		for ip, exp := range s.tempBans {
			if now.After(exp) {
				delete(s.tempBans, ip)
			}
		}
		for ip, hist := range s.strikes {
			if len(hist) == 0 || now.Sub(hist[len(hist)-1]) > 10*time.Minute {
				delete(s.strikes, ip)
			}
		}
		// Clean fingerprint bans and strikes
		for fp, exp := range s.fingerprintBans {
			if now.After(exp) {
				delete(s.fingerprintBans, fp)
			}
		}
		for fp, hist := range s.fingerprintStrikes {
			if len(hist) == 0 || now.Sub(hist[len(hist)-1]) > 10*time.Minute {
				delete(s.fingerprintStrikes, fp)
			}
		}
		s.banMu.Unlock()
	}
}

// IsFingerprintBanned checks if a fingerprint is currently temp-banned.
func (s *Store) IsFingerprintBanned(fp string) (bool, time.Time) {
	if fp == "" {
		return false, time.Time{}
	}
	s.banMu.Lock()
	defer s.banMu.Unlock()
	exp, ok := s.fingerprintBans[fp]
	if !ok {
		return false, time.Time{}
	}
	if time.Now().After(exp) {
		delete(s.fingerprintBans, fp)
		return false, time.Time{}
	}
	return true, exp
}

// AddFingerprintBan installs or extends a temp ban on a fingerprint.
func (s *Store) AddFingerprintBan(fp string, dur time.Duration) {
	if fp == "" || dur <= 0 {
		return
	}
	expiry := time.Now().Add(dur)
	s.banMu.Lock()
	if cur, ok := s.fingerprintBans[fp]; !ok || cur.Before(expiry) {
		s.fingerprintBans[fp] = expiry
	}
	s.banMu.Unlock()
}

// RecordFingerprintStrike adds a block strike for a fingerprint signature.
// If strikes cross the threshold, the fingerprint gets temp-banned.
func (s *Store) RecordFingerprintStrike(fp string) time.Duration {
	if fp == "" {
		return 0
	}
	s.mu.RLock()
	cfg := s.cfg.FingerprintTracking
	s.mu.RUnlock()
	if !cfg.Enabled || cfg.Threshold < 1 {
		return 0
	}
	now := time.Now()
	cutoff := now.Add(-time.Duration(cfg.WindowSeconds) * time.Second)

	s.banMu.Lock()
	hist := s.fingerprintStrikes[fp]
	// Drop strikes outside the window
	keep := hist[:0]
	for _, t := range hist {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	s.fingerprintStrikes[fp] = keep
	count := len(keep)
	s.banMu.Unlock()

	if count >= cfg.Threshold {
		dur := time.Duration(cfg.BanSeconds) * time.Second
		s.AddFingerprintBan(fp, dur)
		// Reset strikes once promoted
		s.banMu.Lock()
		delete(s.fingerprintStrikes, fp)
		s.banMu.Unlock()
		return dur
	}
	return 0
}

// FingerprintBansSnapshot returns a copy of the current fingerprint ban map.
func (s *Store) FingerprintBansSnapshot() map[string]time.Time {
	s.banMu.Lock()
	defer s.banMu.Unlock()
	now := time.Now()
	out := make(map[string]time.Time, len(s.fingerprintBans))
	for k, v := range s.fingerprintBans {
		if v.After(now) {
			out[k] = v
		}
	}
	return out
}

// ClearFingerprintBan removes an active fingerprint ban.
func (s *Store) ClearFingerprintBan(fp string) {
	s.banMu.Lock()
	delete(s.fingerprintBans, fp)
	delete(s.fingerprintStrikes, fp)
	s.banMu.Unlock()
}
