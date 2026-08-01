package guardian

import (
	"net"
	"regexp"
	"strings"
)

// HostMatches returns true if host matches any pattern in patterns.
// An empty or nil patterns slice matches every host (rule is global).
// Patterns use simple glob syntax with `*` as wildcard for any chars
// except `.` (so `*.example.com` matches `foo.example.com` but not
// `foo.bar.example.com`). `**.example.com` would match any subdomain depth.
func HostMatches(host string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	host = normalizeHost(host)
	for _, p := range patterns {
		if matchOne(host, strings.ToLower(strings.TrimSpace(p))) {
			return true
		}
	}
	return false
}

// normalizeHost removes a valid port without corrupting IPv6 authorities.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		// A bracketed IPv6 literal without a port is not an authority form
		// emitted by net/http, but accepting it makes matching predictable.
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return strings.ToLower(host)
}

func matchOne(host, pattern string) bool {
	if pattern == "" || pattern == "*" || pattern == "**" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return host == pattern
	}
	re := globToRegex(pattern)
	matched, err := regexp.MatchString(re, host)
	if err != nil {
		return false
	}
	return matched
}

func globToRegex(p string) string {
	var b strings.Builder
	b.WriteString("^")
	i := 0
	for i < len(p) {
		c := p[i]
		switch c {
		case '*':
			// "**" -> match anything including dots
			if i+1 < len(p) && p[i+1] == '*' {
				b.WriteString(".*")
				i += 2
				continue
			}
			b.WriteString("[^.]*")
		case '?':
			b.WriteString("[^.]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
		i++
	}
	b.WriteString("$")
	return b.String()
}
