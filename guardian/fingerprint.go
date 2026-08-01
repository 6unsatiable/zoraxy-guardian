package guardian

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

// GenerateFingerprint creates a stable hash from a request signature that can
// persist across IP changes: request target, authority, method, User-Agent,
// Accept headers, and HTTP version.
//
// This allows tracking malicious actors even when they rotate IPs or use
// distributed scanners, as long as they reuse the same tooling/headers.
func GenerateFingerprint(req *plugin.DynamicSniffForwardRequest) string {
	// Collect headers in deterministic order
	ua := normalizeHeader(req.Header, "User-Agent")
	accept := normalizeHeader(req.Header, "Accept")
	acceptEnc := normalizeHeader(req.Header, "Accept-Encoding")
	acceptLang := normalizeHeader(req.Header, "Accept-Language")

	// Do not create a shared fingerprint for requests carrying none of the
	// distinguishing headers. Otherwise header-poor clients all collapse to
	// one identity and can be collateral-banned by unrelated traffic.
	if ua == "" && accept == "" && acceptEnc == "" && acceptLang == "" {
		return ""
	}

	// Include HTTP version (HTTP/1.1, HTTP/2, etc.)
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1" // default fallback
	}

	// Build fingerprint string
	parts := []string{
		"ua=" + ua,
		"accept=" + accept,
		"enc=" + acceptEnc,
		"lang=" + acceptLang,
		"proto=" + proto,
		"host=" + normalizeHost(req.Host),
		"method=" + strings.ToUpper(req.Method),
		"target=" + req.RequestURI,
	}

	raw := strings.Join(parts, "|")

	// Hash to keep it compact (32 chars hex)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])[:16] // Use first 16 chars for readability
}

// normalizeHeader extracts a header value and normalizes it for fingerprinting.
// Returns lowercase, sorted comma-separated values for deterministic hashing.
func normalizeHeader(headers map[string][]string, name string) string {
	for k, values := range headers {
		if strings.EqualFold(k, name) {
			if len(values) == 0 {
				return ""
			}
			// Join multi-value headers, lowercase, trim spaces
			combined := strings.Join(values, ",")
			parts := strings.Split(combined, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(strings.ToLower(parts[i]))
			}
			// Sort for deterministic order (e.g., "gzip, br" vs "br, gzip")
			sort.Strings(parts)
			return strings.Join(parts, ",")
		}
	}
	return ""
}
