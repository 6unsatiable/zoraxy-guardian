package guardian

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAtomicWriteLeavesNoTmpOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := atomicWriteFile(path, []byte(`{"x":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") || strings.Contains(e.Name(), ".tmp") {
			t.Errorf("found stray tmp file: %s", e.Name())
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"x":1}` {
		t.Fatalf("got %q, err=%v", data, err)
	}
}

func TestAtomicWriteOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	_ = os.WriteFile(path, []byte("old"), 0o644)
	if err := atomicWriteFile(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "new" {
		t.Errorf("got %q want new", data)
	}
}

func TestUpdateDoesNotApplyConfigWhenPersistenceFails(t *testing.T) {
	s := newStore(t, Config{IPBlocklist: []ScopedEntry{{Value: "192.0.2.1"}}})
	s.configPath = filepath.Join(t.TempDir(), "missing", "config.json")

	if err := s.Update(Config{IPBlocklist: []ScopedEntry{{Value: "198.51.100.1"}}}); err == nil {
		t.Fatal("Update succeeded despite an unavailable config directory")
	}
	cfg := s.Snapshot()
	if len(cfg.IPBlocklist) != 1 || cfg.IPBlocklist[0].Value != "192.0.2.1" {
		t.Fatalf("live config changed after failed persistence: %+v", cfg.IPBlocklist)
	}
}

func TestUpdateRejectsInvalidRuleWithoutChangingLiveConfig(t *testing.T) {
	s := newStore(t, Config{IPBlocklist: []ScopedEntry{{Value: "192.0.2.1"}}})
	if err := s.Update(Config{IPBlocklist: []ScopedEntry{{Value: "not-an-ip"}}}); err == nil {
		t.Fatal("Update accepted an invalid IP rule")
	}
	cfg := s.Snapshot()
	if len(cfg.IPBlocklist) != 1 || cfg.IPBlocklist[0].Value != "192.0.2.1" {
		t.Fatalf("live config changed after invalid update: %+v", cfg.IPBlocklist)
	}
}

func TestPendingDecisionsExpireAndAreBounded(t *testing.T) {
	s := newStore(t, Config{})
	old := pendingDecision{decision: Decision{Block: true}, created: time.Now().Add(-pendingDecisionTTL - time.Second)}
	s.pending["expired"] = old
	s.RecordDecision("fresh", Decision{Block: true, Reason: "test"})
	if _, ok := s.pending["expired"]; ok {
		t.Fatal("expired pending decision was not evicted")
	}
	if d, ok := s.TakeDecision("fresh"); !ok || d.Reason != "test" {
		t.Fatalf("fresh decision = %+v, ok=%v", d, ok)
	}

	for i := 0; i < maxPendingDecisions+100; i++ {
		s.RecordDecision(strconv.Itoa(i), Decision{Block: true})
	}
	if len(s.pending) > maxPendingDecisions {
		t.Fatalf("pending decisions = %d, cap = %d", len(s.pending), maxPendingDecisions)
	}
}
