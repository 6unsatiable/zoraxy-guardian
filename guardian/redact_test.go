package guardian

import "testing"

func TestRedactRequestURI(t *testing.T) {
	got := redactRequestURI("/login?next=%2Fdashboard&token=secret&Password=hunter2")
	want := "/login?Password=REDACTED&next=%2Fdashboard&token=REDACTED"
	if got != want {
		t.Fatalf("redacted URI = %q, want %q", got, want)
	}
	if got := redactRequestURI("/health?full=true"); got != "/health?full=true" {
		t.Fatalf("safe URI changed: %q", got)
	}
}

func TestLogEntryRedactsRequestURI(t *testing.T) {
	s := newStore(t, Config{})
	s.LogEntry(BlockLogEntry{RequestURI: "/?access_token=secret", Reason: "test"})
	entries := s.LogPage(0, 0)
	if len(entries) != 1 || entries[0].RequestURI != "/?access_token=REDACTED" {
		t.Fatalf("log entries = %#v, expected redacted request URI", entries)
	}
}
