package guardian

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
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
