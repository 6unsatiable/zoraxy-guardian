package guardian

import "testing"

func TestHostMatches(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		patterns []string
		want     bool
	}{
		{"empty patterns matches all", "foo.example.com", nil, true},
		{"empty slice matches all", "foo.example.com", []string{}, true},
		{"exact match", "example.com", []string{"example.com"}, true},
		{"exact mismatch", "other.com", []string{"example.com"}, false},
		{"wildcard subdomain", "foo.example.com", []string{"*.example.com"}, true},
		{"wildcard does not cross dots", "a.b.example.com", []string{"*.example.com"}, false},
		{"double-wildcard crosses dots", "a.b.example.com", []string{"**.example.com"}, true},
		{"port stripped", "example.com:8443", []string{"example.com"}, true},
		{"IPv6 authority port stripped", "[2001:db8::1]:443", []string{"2001:db8::1"}, true},
		{"bare IPv6 exact match", "2001:db8::1", []string{"2001:db8::1"}, true},
		{"case insensitive", "Example.COM", []string{"example.com"}, true},
		{"any of multiple", "foo.example.com", []string{"a.com", "*.example.com"}, true},
		{"none match", "foo.example.com", []string{"a.com", "b.com"}, false},
		{"star alone matches all", "anything.tld", []string{"*"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HostMatches(tc.host, tc.patterns); got != tc.want {
				t.Errorf("HostMatches(%q, %v) = %v, want %v", tc.host, tc.patterns, got, tc.want)
			}
		})
	}
}
