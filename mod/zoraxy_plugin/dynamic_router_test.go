package zoraxy_plugin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDynamicSniffRejectsOversizedPayload(t *testing.T) {
	mux := http.NewServeMux()
	router := NewPathRouter()
	called := false
	router.RegisterDynamicSniffHandler("/sniff", mux, func(*DynamicSniffForwardRequest) SniffResult {
		called = true
		return SniffResultSkip
	})

	req := httptest.NewRequest(http.MethodPost, "/sniff/", strings.NewReader(strings.Repeat("x", maxDynamicSniffPayload+1)))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
	if called {
		t.Fatal("sniff handler was called for an oversized payload")
	}
}
