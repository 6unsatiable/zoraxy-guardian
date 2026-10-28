package guardian

import "testing"

func TestCloudflareOnly(t *testing.T) {
	s := newStore(t, Config{
		CloudflareOnly: true,
		DirectHosts:    []string{"notes.example.com"},
		ExemptCIDRs:    []string{"198.51.100.7"},
	})
	cases := []struct {
		name, host, ip string
		block          bool
	}{
		{"direct host from internet", "notes.example.com", "203.0.113.5", false},
		{"direct host with port", "Notes.Example.com:443", "203.0.113.5", false},
		{"fronted host from internet", "app.example.com", "203.0.113.5", true},
		{"via cloudflare", "app.example.com", "104.16.1.1", false},
		{"from lan", "app.example.com", "192.168.1.50", false},
		{"exempt client", "app.example.com", "198.51.100.7", false},
		{"ipv6 internet", "app.example.com", "2001:db8::1", true},
		{"ipv6 cloudflare", "app.example.com", "2606:4700::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := s.Evaluate(req(tc.host, tc.ip, "Mozilla/5.0", "/"))
			if got := d.Block && d.Reason == "origin-bypass"; got != tc.block {
				t.Errorf("block=%v reason=%q, want origin-bypass block=%v", d.Block, d.Reason, tc.block)
			}
		})
	}
	// A forged CF-Connecting-IP from a non-Cloudflare peer doesn't help.
	r := req("app.example.com", "203.0.113.5", "Mozilla/5.0", "/")
	r.Header["Cf-Connecting-Ip"] = []string{"192.168.1.2"}
	r.Header["X-Forwarded-For"] = []string{"192.168.1.2"}
	if d := s.Evaluate(r); d.Reason != "origin-bypass" {
		t.Errorf("forged headers: got %+v", d)
	}
}

func TestCloudflareOnlyOffOrEmptyHosts(t *testing.T) {
	if d := newStore(t, Config{}).Evaluate(req("app.example.com", "203.0.113.5", "Mozilla/5.0", "/")); d.Reason == "origin-bypass" {
		t.Error("blocked while off")
	}
	// Empty DirectHosts must not mean "every host" (HostMatches' default).
	if d := newStore(t, Config{CloudflareOnly: true}).Evaluate(req("notes.example.com", "203.0.113.5", "Mozilla/5.0", "/")); d.Reason != "origin-bypass" {
		t.Errorf("empty direct_hosts let it through: %+v", d)
	}
}
