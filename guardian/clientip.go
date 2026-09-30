package guardian

import (
	"net"
	"strings"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

// cloudflareCIDRs are Cloudflare's published edge ranges
// (https://www.cloudflare.com/ips-v4 and /ips-v6, checked 2026-09-30). When
// Config.TrustCloudflare is on they are treated as trusted proxies, and
// CF-Connecting-IP is honored for connections that really come from them.
var cloudflareCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var cloudflareRules = compileIPRules(scopedEntries(cloudflareCIDRs))

// isCloudflareIP reports whether ip belongs to Cloudflare's edge network.
func isCloudflareIP(ip net.IP) bool {
	return ip != nil && ipInRules(ip, cloudflareRules)
}

// clientIP resolves the address that rules, bans and rate limits apply to.
//
//  1. The direct peer (RemoteAddr) is used unless it is a trusted proxy.
//  2. For a trusted peer, CF-Connecting-IP is honored only when the peer is a
//     Cloudflare address (anyone else could forge that header), then
//     X-Forwarded-For is walked right to left to the first untrusted hop,
//     then X-Real-IP.
//  3. For an untrusted peer, Zoraxy's own client_ip (Zoraxy v3.3.5+) is used
//     when it differs from the peer: Zoraxy only sets a different value after
//     resolving the headers through its own trusted-proxy list.
func clientIP(req *plugin.DynamicSniffForwardRequest, trustedProxies []compiledIPRule) string {
	remote := remoteIP(req.RemoteAddr)
	zoraxyIP := net.ParseIP(strings.TrimSpace(req.ClientIP))
	if remote == nil {
		if zoraxyIP != nil {
			return zoraxyIP.String()
		}
		return req.RemoteAddr
	}
	if !ipInRules(remote, trustedProxies) {
		if zoraxyIP != nil && !zoraxyIP.Equal(remote) {
			return zoraxyIP.String()
		}
		return remote.String()
	}

	if isCloudflareIP(remote) {
		if ip := net.ParseIP(strings.TrimSpace(firstHeader(req.Header, "CF-Connecting-IP"))); ip != nil {
			return ip.String()
		}
	}
	if xff := allHeaderValues(req.Header, "X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := net.ParseIP(strings.TrimSpace(parts[i]))
			if ip == nil {
				// A malformed hop means the chain can't be trusted past this
				// point; fall back to the peer rather than guess.
				return remote.String()
			}
			if !ipInRules(ip, trustedProxies) {
				return ip.String()
			}
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(firstHeader(req.Header, "X-Real-IP"))); ip != nil {
		return ip.String()
	}
	return remote.String()
}

// isProxyAddress reports whether a resolved client address is actually a
// proxy: a configured trusted proxy or any Cloudflare edge. That happens when
// traffic arrives through a proxy Guardian was not told to trust. Such an
// address must never be banned, struck or rate limited: it is shared by
// every visitor that proxy serves.
func isProxyAddress(ip net.IP, trustedProxies []compiledIPRule) bool {
	return ip != nil && (ipInRules(ip, trustedProxies) || isCloudflareIP(ip))
}

// banKey is the key temp bans, strikes and rate limits are tracked under.
// IPv4 addresses are used as-is. IPv6 clients are grouped by /64, the
// smallest block a home or VPS connection is normally assigned, so a client
// can't dodge a ban by rotating through its own subnet.
func banKey(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return strings.TrimSpace(ip)
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return (&net.IPNet{IP: parsed.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

// normalizeBanKey turns user input for "clear ban" (an IP, an IPv6 /64 in
// CIDR form, or a raw key) into the stored key.
func normalizeBanKey(value string) string {
	value = strings.TrimSpace(value)
	if _, n, err := net.ParseCIDR(value); err == nil {
		ones, bits := n.Mask.Size()
		if bits == 128 && ones == 64 {
			return n.String()
		}
		return banKey(n.IP.String())
	}
	return banKey(value)
}

func allHeaderValues(h map[string][]string, name string) string {
	var values []string
	for k, v := range h {
		if strings.EqualFold(k, name) {
			values = append(values, v...)
		}
	}
	return strings.Join(values, ",")
}
