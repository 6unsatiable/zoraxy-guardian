package guardian

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Challenge puts a JavaScript proof-of-work in front of browser-facing
// hosts. A browser solves it once (well under a second) and gets a signed
// cookie; scrapers that don't run JavaScript never get past it. Only
// top-level page loads are challenged: API calls, assets and anything sending
// credentials go through the non-interactive checks instead, so apps keep
// working.
type Challenge struct {
	Enabled bool `json:"enabled"`
	// Hosts the challenge applies to (globs). Empty means none.
	Hosts []string `json:"hosts"`
	// Difficulty in leading zero bits of SHA-256 (16 = ~65k hashes).
	Difficulty int `json:"difficulty"`
	// CookieHours is how long a solved challenge stays valid.
	CookieHours int `json:"cookie_hours"`
	// BindCookieToNetwork ties the cookie to the client's /24 (IPv4) or /48
	// (IPv6), so a stolen cookie is useless from another network. Off by
	// default: phones that hop between mobile and Wi-Fi would be challenged
	// again.
	BindCookieToNetwork bool `json:"bind_cookie_to_network"`
	// ExemptPaths are path prefixes that are never challenged (APIs,
	// webhooks, manifests). Host-scoped via Hosts.
	ExemptPaths []ScopedEntry `json:"exempt_paths"`
	// AppUserAgents are regexes for native apps that load pages without
	// running JavaScript; they get the non-interactive checks instead.
	AppUserAgents []ScopedEntry `json:"app_user_agents"`
}

const (
	challengeCookie = "__guardian"
	verifyPath      = "/.guardian/verify"
	challengeTTL    = 5 * time.Minute
)

var defaultChallengeExemptPaths = []string{
	"/api/", "/ws", "/socket.io/", "/.well-known/", "/robots.txt", "/favicon.ico",
	"/manifest.json", "/site.webmanifest", "/manifest.webmanifest", "/sw.js", "/service-worker.js",
}

var staticExtensions = []string{
	".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".otf", ".mp4", ".webm", ".m3u8", ".m4s", ".ts", ".mp3", ".wasm", ".json",
}

// loadSecret reads (or creates) the HMAC key used for challenges and
// cookies. It lives beside config.json, not in it, so it never reaches the UI.
func loadSecret(path string) []byte {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	_ = atomicWriteFile(path, b, 0o600)
	return b
}

func (s *Store) mac(parts ...string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(m.Sum(nil))
}

func uaHash(ua string) string {
	h := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(h[:8])
}

// newChallenge returns "ts.rand.mac", bound to the client, browser and host.
func (s *Store) newChallenge(ipKey, ua, host string, now time.Time) string {
	r := make([]byte, 8)
	_, _ = rand.Read(r)
	ts := strconv.FormatInt(now.Unix(), 10)
	rs := hex.EncodeToString(r)
	return ts + "." + rs + "." + s.mac("c", ts, rs, ipKey, uaHash(ua), host)[:32]
}

func (s *Store) checkChallenge(c, nonce, ipKey, ua, host string, difficulty int, now time.Time) bool {
	p := strings.Split(c, ".")
	if len(p) != 3 || len(nonce) == 0 || len(nonce) > 32 {
		return false
	}
	want := s.mac("c", p[0], p[1], ipKey, uaHash(ua), host)[:32]
	if !hmac.Equal([]byte(want), []byte(p[2])) {
		return false
	}
	ts, err := strconv.ParseInt(p[0], 10, 64)
	if err != nil {
		return false
	}
	age := now.Sub(time.Unix(ts, 0))
	if age < -time.Minute || age > challengeTTL {
		return false
	}
	sum := sha256.Sum256([]byte(c + nonce))
	if leadingZeroBits(sum[:]) < difficulty {
		return false
	}
	// One solved challenge earns one cookie: without this, a single solve
	// could be replayed for the whole 5 minutes to mint unlimited cookies.
	return s.consumeChallenge(p[0]+"."+p[1], now)
}

// consumeChallenge records a challenge as used and reports whether this was
// its first use.
func (s *Store) consumeChallenge(id string, now time.Time) bool {
	s.usedMu.Lock()
	defer s.usedMu.Unlock()
	if s.usedChallenges == nil {
		s.usedChallenges = make(map[string]time.Time)
	}
	if _, used := s.usedChallenges[id]; used {
		return false
	}
	if len(s.usedChallenges) >= maxTrackedKeys {
		for k, exp := range s.usedChallenges {
			if now.After(exp) {
				delete(s.usedChallenges, k)
			}
		}
		if len(s.usedChallenges) >= maxTrackedKeys {
			// Refuse rather than forget: an attacker flooding solves must
			// not be able to flush the replay record.
			return false
		}
	}
	s.usedChallenges[id] = now.Add(challengeTTL + 2*time.Minute)
	return true
}

// networkKey is the client network a cookie is bound to ("" when binding is
// off or the address is unusable).
func networkKey(ip string, bind bool) string {
	if !bind {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String()
	}
	return parsed.Mask(net.CIDRMask(48, 128)).String()
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(x)
	}
	return n
}

func (s *Store) cookieValue(host, ua, netKey string, exp time.Time) string {
	e := strconv.FormatInt(exp.Unix(), 10)
	return e + "." + s.mac("k", host, e, uaHash(ua), netKey)[:32]
}

func (s *Store) validCookie(header map[string][]string, host, ua, netKey string, now time.Time) bool {
	for _, line := range headerValues(header, "Cookie") {
		for _, part := range strings.Split(line, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || k != challengeCookie {
				continue
			}
			e, sig, ok := strings.Cut(v, ".")
			if !ok {
				continue
			}
			exp, err := strconv.ParseInt(e, 10, 64)
			if err != nil || now.Unix() > exp {
				continue
			}
			want := s.mac("k", host, e, uaHash(ua), netKey)[:32]
			if hmac.Equal([]byte(want), []byte(sig)) {
				return true
			}
		}
	}
	return false
}

func headerValues(h map[string][]string, name string) []string {
	var out []string
	for k, v := range h {
		if strings.EqualFold(k, name) {
			out = append(out, v...)
		}
	}
	return out
}

// safeReturnPath keeps the post-challenge redirect on the same site.
func safeReturnPath(r string) string {
	if !strings.HasPrefix(r, "/") || strings.HasPrefix(r, "//") || strings.HasPrefix(r, "/\\") ||
		strings.ContainsAny(r, "\r\n") || strings.HasPrefix(r, verifyPath) {
		return "/"
	}
	return r
}

// challengeDecision serves the proof-of-work page.
func (s *Store) challengeDecision(ip, ipKey, ua, host, returnTo string, difficulty int) Decision {
	c := s.newChallenge(ipKey, ua, host, time.Now())
	body := strings.NewReplacer(
		"{{C}}", c,
		"{{D}}", strconv.Itoa(difficulty),
		"{{R}}", url.QueryEscape(returnTo), // only [A-Za-z0-9%+._~-]: safe in a JS string
	).Replace(challengePage)
	return Decision{
		Block:  true,
		Kind:   KindChallenge,
		Reason: "challenge",
		Status: http.StatusForbidden,
		IP:     ip,
		Body:   []byte(body),
		Headers: map[string]string{
			"Content-Type":            "text/html; charset=utf-8",
			"X-Robots-Tag":            "noindex, nofollow",
			"Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'",
		},
	}
}

// verifyDecision handles /.guardian/verify: a correct solution earns the
// cookie and a redirect back; anything else gets a fresh challenge.
func (s *Store) verifyDecision(rawQuery, ip, ipKey, ua, host string, difficulty, cookieHours int, bind bool) Decision {
	q, _ := url.ParseQuery(rawQuery)
	ret := safeReturnPath(q.Get("r"))
	if !s.checkChallenge(q.Get("c"), q.Get("n"), ipKey, ua, host, difficulty, time.Now()) {
		d := s.challengeDecision(ip, ipKey, ua, host, ret, difficulty)
		d.Reason = "challenge-failed"
		return d
	}
	ttl := time.Duration(cookieHours) * time.Hour
	val := s.cookieValue(host, ua, networkKey(ip, bind), time.Now().Add(ttl))
	return Decision{
		Block:  true,
		Kind:   KindRedirect,
		Reason: "challenge-passed",
		Status: http.StatusFound,
		IP:     ip,
		Headers: map[string]string{
			// Absolute: Zoraxy rewrites a relative Location against the
			// plugin's capture path. host is always a listed challenge host.
			"Location":   "https://" + host + ret,
			"Set-Cookie": fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax", challengeCookie, val, int(ttl.Seconds())),
		},
	}
}

// challengePage is self-contained (no external requests). The SHA-256 is a
// small synchronous implementation because crypto.subtle's per-call promise
// overhead makes a proof-of-work several times slower on phones.
const challengePage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Checking your browser…</title>
<style>body{font-family:system-ui,sans-serif;background:#111;color:#ddd;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.b{text-align:center;max-width:24rem;padding:1rem}.s{width:2rem;height:2rem;border:3px solid #444;border-top-color:#8ab4f8;border-radius:50%;animation:r 1s linear infinite;margin:0 auto 1rem}
@keyframes r{to{transform:rotate(360deg)}}small{color:#888}</style></head>
<body><div class="b"><div class="s"></div><p id="m">Checking your browser…</p>
<noscript><p>JavaScript is required to continue.</p></noscript><small>Guardian</small></div>
<script>
(function(){
var C="{{C}}",D={{D}},R="{{R}}";
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
var W=new Int32Array(64);
function h(s){var n=s.length,l=((n+8)>>6)+1,m=new Int32Array(l*16),i,j;
for(i=0;i<n;i++)m[i>>2]|=s.charCodeAt(i)<<(24-(i&3)*8);
m[n>>2]|=0x80<<(24-(n&3)*8);m[l*16-1]=n*8;
var a0=0x6a09e667,b0=0xbb67ae85|0,c0=0x3c6ef372,d0=0xa54ff53a|0,e0=0x510e527f,f0=0x9b05688c|0,g0=0x1f83d9ab,h0=0x5be0cd19;
for(j=0;j<l*16;j+=16){var a=a0,b=b0,c=c0,d=d0,e=e0,f=f0,g=g0,k=h0,t1,t2,x,y;
for(i=0;i<64;i++){if(i<16)W[i]=m[j+i];else{x=W[i-15];y=W[i-2];
W[i]=(((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3))+W[i-16]+(((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10))+W[i-7]|0;}
t1=k+(((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7)))+((e&f)^(~e&g))+K[i]+W[i]|0;
t2=(((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10)))+((a&b)^(a&c)^(b&c))|0;
k=g;g=f;f=e;e=d+t1|0;d=c;c=b;b=a;a=t1+t2|0;}
a0=a0+a|0;b0=b0+b|0;c0=c0+c|0;d0=d0+d|0;e0=e0+e|0;f0=f0+f|0;g0=g0+g|0;h0=h0+k|0;}
return [a0,b0];}
function z(v){var x=v[0],n=0;if(x===0){n=32;x=v[1];if(x===0)return 64;}return n+Math.clz32(x);}
var nonce=0;
function step(){var end=nonce+20000;for(;nonce<end;nonce++){if(z(h(C+nonce))>=D){
location.replace("/.guardian/verify?c="+encodeURIComponent(C)+"&n="+nonce+"&r="+R);return;}}
setTimeout(step,0);}
setTimeout(step,0);
})();
</script></body></html>`
