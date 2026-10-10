package guardian

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHoneypotTripInstallsTempBan(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(filepath.Join(dir, "cfg.json"), filepath.Join(dir, "log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.Snapshot()
	cfg.Honeypot.Enabled = true
	cfg.Honeypot.BanSeconds = 60
	cfg.Honeypot.Paths = []ScopedEntry{{Value: "/.env"}}
	if err := s.Update(cfg); err != nil {
		t.Fatal(err)
	}

	// Hit the honeypot path.
	r := req("x.test", "203.0.113.7", "ua", "/.env")
	d := s.Evaluate(r)
	if !d.Block || d.Reason != "honeypot" {
		t.Fatalf("expected honeypot block, got %+v", d)
	}
	if banned, _ := s.IsTempBanned("203.0.113.7"); !banned {
		t.Fatal("expected temp ban after honeypot trip")
	}

	// Now an unrelated request from the same IP should be blocked by temp-ban.
	r2 := req("other.test", "203.0.113.7", "ua", "/normal/path")
	d2 := s.Evaluate(r2)
	if !d2.Block || d2.Reason != "temp-ban" {
		t.Fatalf("expected temp-ban block on follow-up, got %+v", d2)
	}

	// Different IP unaffected.
	r3 := req("other.test", "198.51.100.1", "ua", "/normal/path")
	if d := s.Evaluate(r3); d.Block {
		t.Errorf("unrelated IP should pass, got %+v", d)
	}
}

func TestHoneypotDisabledNoOp(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(filepath.Join(dir, "cfg.json"), filepath.Join(dir, "log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.Snapshot()
	cfg.Honeypot.Enabled = false
	cfg.Honeypot.Paths = []ScopedEntry{{Value: "/.env"}}
	cfg.WAFEngine.Enabled = false // CRS blocks /.env on its own
	if err := s.Update(cfg); err != nil {
		t.Fatal(err)
	}
	r := req("x.test", "203.0.113.8", "ua", "/.env")
	if d := s.Evaluate(r); d.Block {
		t.Errorf("disabled honeypot should not fire, got %+v", d)
	}
}

func TestAutoBanEscalates(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(filepath.Join(dir, "cfg.json"), filepath.Join(dir, "log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.Snapshot()
	cfg.UABlocklist = []ScopedEntry{{Value: `(?i)sqlmap`}}
	cfg.AutoBan = AutoBan{Enabled: true, Threshold: 3, WindowSeconds: 60, BanSeconds: 60}
	if err := s.Update(cfg); err != nil {
		t.Fatal(err)
	}
	ip := "192.0.2.42"
	for i := 0; i < 2; i++ {
		d := s.Evaluate(req("x.test", ip, "sqlmap/1.0", "/"))
		if d.Reason != "ua-blocklist" {
			t.Fatalf("strike %d: expected ua-blocklist, got %+v", i, d)
		}
	}
	if banned, _ := s.IsTempBanned(ip); banned {
		t.Fatalf("temp ban installed before threshold reached")
	}
	// Third strike — threshold = 3 — should promote to temp ban.
	d := s.Evaluate(req("x.test", ip, "sqlmap/1.0", "/"))
	if d.Reason != "ua-blocklist" {
		t.Fatalf("third strike: expected ua-blocklist, got %+v", d)
	}
	if banned, _ := s.IsTempBanned(ip); !banned {
		t.Fatal("expected temp ban after threshold strikes")
	}
}

func TestClearTempBan(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(filepath.Join(dir, "cfg.json"), filepath.Join(dir, "log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s.AddTempBan("9.9.9.9", time.Hour)
	if banned, _ := s.IsTempBanned("9.9.9.9"); !banned {
		t.Fatal("expected ban active")
	}
	s.ClearTempBan("9.9.9.9")
	if banned, _ := s.IsTempBanned("9.9.9.9"); banned {
		t.Fatal("expected ban cleared")
	}
}

func TestTempBanExpiry(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(filepath.Join(dir, "cfg.json"), filepath.Join(dir, "log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s.AddTempBan("9.9.9.9", 10*time.Millisecond)
	if banned, _ := s.IsTempBanned("9.9.9.9"); !banned {
		t.Fatal("expected ban active")
	}
	time.Sleep(30 * time.Millisecond)
	if banned, _ := s.IsTempBanned("9.9.9.9"); banned {
		t.Fatal("expected ban expired")
	}
}
