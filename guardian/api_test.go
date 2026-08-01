package guardian

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestBlockLogRejectsNegativePaginationWithoutPanicking(t *testing.T) {
	s := newStore(t, Config{})
	s.LogEntry(BlockLogEntry{Reason: "test", Status: http.StatusForbidden})
	a := NewAPI(s)

	req := httptest.NewRequest(http.MethodGet, "/api/blocklog?offset=-1&limit=-1", nil)
	rr := httptest.NewRecorder()
	a.handleBlockLog(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	var got struct {
		Offset  int             `json:"offset"`
		Limit   int             `json:"limit"`
		Entries []BlockLogEntry `json:"entries"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Reason != "test" {
		t.Fatalf("entries = %#v, want the logged entry", got.Entries)
	}
	if got.Offset != 0 || got.Limit != 0 {
		t.Fatalf("pagination = offset %d, limit %d; want normalized zero values", got.Offset, got.Limit)
	}
}

func TestBlockLogLargeLimitDoesNotOverflow(t *testing.T) {
	s := newStore(t, Config{})
	s.LogEntry(BlockLogEntry{Reason: "test", Status: http.StatusForbidden})
	a := NewAPI(s)

	req := httptest.NewRequest(http.MethodGet, "/api/blocklog?offset=0&limit="+strconv.FormatInt(math.MaxInt64, 10), nil)
	rr := httptest.NewRecorder()
	a.handleBlockLog(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestBlockLogSummaryAndExport(t *testing.T) {
	s := newStore(t, Config{})
	s.LogEntry(BlockLogEntry{IP: "203.0.113.9", Reason: "waf-xss", RequestURI: "/?token=secret"})
	s.LogEntry(BlockLogEntry{IP: "203.0.113.9", Reason: "waf-xss", RequestURI: "/ok"})
	s.LogEntry(BlockLogEntry{IP: "198.51.100.1", Reason: "rate-limit"})
	a := NewAPI(s)

	summaryReq := httptest.NewRequest(http.MethodGet, "/api/blocklog/summary", nil)
	summaryRR := httptest.NewRecorder()
	a.handleBlockLogSummary(summaryRR, summaryReq)
	var summary BlockLogSummary
	if err := json.NewDecoder(summaryRR.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.Total != 3 || len(summary.TopIPs) == 0 || summary.TopIPs[0] != (BlockLogCount{Value: "203.0.113.9", Count: 2}) {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/api/blocklog/export?format=csv", nil)
	exportRR := httptest.NewRecorder()
	a.handleBlockLogExport(exportRR, exportReq)
	if exportRR.Code != http.StatusOK || !strings.Contains(exportRR.Body.String(), "token=REDACTED") {
		t.Fatalf("CSV export was not redacted: status=%d body=%q", exportRR.Code, exportRR.Body.String())
	}
}

func TestRecommendedRulesPreviewAndApply(t *testing.T) {
	s := newStore(t, Config{UABlocklist: []ScopedEntry{{Value: `(?i)sqlmap`}}})
	a := NewAPI(s)

	previewReq := httptest.NewRequest(http.MethodPost, "/api/rules/recommended", bytes.NewBufferString(`{"apply":false}`))
	previewRR := httptest.NewRecorder()
	a.handleRecommendedRules(previewRR, previewReq)
	if previewRR.Code != http.StatusOK || len(s.Snapshot().UABlocklist) != 1 {
		t.Fatalf("preview changed state or failed: status=%d cfg=%+v", previewRR.Code, s.Snapshot())
	}

	applyReq := httptest.NewRequest(http.MethodPost, "/api/rules/recommended", bytes.NewBufferString(`{"apply":true}`))
	applyRR := httptest.NewRecorder()
	a.handleRecommendedRules(applyRR, applyReq)
	if applyRR.Code != http.StatusOK || len(s.Snapshot().UABlocklist) != 3 {
		t.Fatalf("apply did not consolidate defaults: status=%d cfg=%+v", applyRR.Code, s.Snapshot())
	}
}
