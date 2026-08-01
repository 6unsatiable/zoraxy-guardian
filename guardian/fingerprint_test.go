package guardian

import (
	"testing"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

func TestFingerprintGeneration(t *testing.T) {
	// Same headers should produce same fingerprint
	req1 := &plugin.DynamicSniffForwardRequest{
		Proto: "HTTP/1.1",
		Header: map[string][]string{
			"User-Agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
			"Accept":          {"text/html,application/xhtml+xml"},
			"Accept-Encoding": {"gzip, deflate, br"},
			"Accept-Language": {"en-US,en;q=0.9"},
		},
	}

	req2 := &plugin.DynamicSniffForwardRequest{
		Proto: "HTTP/1.1",
		Header: map[string][]string{
			"User-Agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
			"Accept":          {"text/html,application/xhtml+xml"},
			"Accept-Encoding": {"gzip, deflate, br"},
			"Accept-Language": {"en-US,en;q=0.9"},
		},
	}

	fp1 := GenerateFingerprint(req1)
	fp2 := GenerateFingerprint(req2)

	if fp1 != fp2 {
		t.Errorf("Expected identical fingerprints, got %s and %s", fp1, fp2)
	}

	if len(fp1) != 16 {
		t.Errorf("Expected 16-char fingerprint, got %d chars", len(fp1))
	}
}

func TestFingerprintDifferentUA(t *testing.T) {
	// Different User-Agent should produce different fingerprint
	req1 := &plugin.DynamicSniffForwardRequest{
		Proto: "HTTP/1.1",
		Header: map[string][]string{
			"User-Agent": {"curl/7.68.0"},
			"Accept":     {"*/*"},
		},
	}

	req2 := &plugin.DynamicSniffForwardRequest{
		Proto: "HTTP/1.1",
		Header: map[string][]string{
			"User-Agent": {"sqlmap/1.5"},
			"Accept":     {"*/*"},
		},
	}

	fp1 := GenerateFingerprint(req1)
	fp2 := GenerateFingerprint(req2)

	if fp1 == fp2 {
		t.Errorf("Expected different fingerprints for different UAs, got %s", fp1)
	}
}

func TestFingerprintHeaderOrder(t *testing.T) {
	// Header order shouldn't matter (normalization)
	req1 := &plugin.DynamicSniffForwardRequest{
		Proto: "HTTP/2",
		Header: map[string][]string{
			"Accept-Encoding": {"gzip, br"},
		},
	}

	req2 := &plugin.DynamicSniffForwardRequest{
		Proto: "HTTP/2",
		Header: map[string][]string{
			"Accept-Encoding": {"br, gzip"},
		},
	}

	fp1 := GenerateFingerprint(req1)
	fp2 := GenerateFingerprint(req2)

	if fp1 != fp2 {
		t.Errorf("Expected identical fingerprints after normalization, got %s and %s", fp1, fp2)
	}
}

func TestFingerprintCaseInsensitive(t *testing.T) {
	// Case shouldn't matter
	req1 := &plugin.DynamicSniffForwardRequest{
		Proto: "HTTP/1.1",
		Header: map[string][]string{
			"Accept": {"text/HTML"},
		},
	}

	req2 := &plugin.DynamicSniffForwardRequest{
		Proto: "HTTP/1.1",
		Header: map[string][]string{
			"Accept": {"TEXT/html"},
		},
	}

	fp1 := GenerateFingerprint(req1)
	fp2 := GenerateFingerprint(req2)

	if fp1 != fp2 {
		t.Errorf("Expected identical fingerprints (case-insensitive), got %s and %s", fp1, fp2)
	}
}

func TestFingerprintRequiresDistinguishingHeaders(t *testing.T) {
	req := &plugin.DynamicSniffForwardRequest{Proto: "HTTP/1.1", Header: map[string][]string{}}
	if got := GenerateFingerprint(req); got != "" {
		t.Errorf("empty distinguishing headers fingerprint = %q, want empty", got)
	}
}
