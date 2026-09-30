package guardian

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

type API struct {
	store *Store
}

func NewAPI(s *Store) *API { return &API{store: s} }

func (a *API) RegisterRoutes(ui *plugin.PluginUiRouter, mux *http.ServeMux) {
	ui.HandleFunc("/api/config", a.handleConfig, mux)
	ui.HandleFunc("/api/blocklog", a.handleBlockLog, mux)
	ui.HandleFunc("/api/blocklog/export", a.handleBlockLogExport, mux)
	ui.HandleFunc("/api/blocklog/summary", a.handleBlockLogSummary, mux)
	ui.HandleFunc("/api/blocklog/stream", a.handleBlockLogStream, mux)
	ui.HandleFunc("/api/tempbans", a.handleTempBans, mux)
	ui.HandleFunc("/api/tempbans/clear", a.handleTempBansClear, mux)
	ui.HandleFunc("/api/fingerprintbans", a.handleFingerprintBans, mux)
	ui.HandleFunc("/api/fingerprintbans/clear", a.handleFingerprintBansClear, mux)
	ui.HandleFunc("/api/import/cf", a.handleImportCF, mux)
	ui.HandleFunc("/api/rules/recommended", a.handleRecommendedRules, mux)
	ui.HandleFunc("/api/status", a.handleStatus, mux)
}

// handleStatus reports health signals the UI shows as banners: traffic that
// arrived through a proxy Guardian doesn't trust, and suppressed log repeats.
func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"untrusted_proxy":    a.store.ProxyWarningSnapshot(),
		"suppressed_repeats": a.store.SuppressedRepeats(),
		"temp_bans":          len(a.store.TempBansSnapshot()),
	})
}

// writeUpdateError maps a Store.Update failure to 400 (bad config, the
// message says what to fix) or 500 (could not be saved).
func writeUpdateError(w http.ResponseWriter, err error) {
	var verr *ValidationError
	if errors.As(err, &verr) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// csvSafe neutralizes spreadsheet formulas. User-Agent and URI come from
// attackers, and a cell like =HYPERLINK(...) would run when the export is
// opened in Excel or Sheets.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func sourceParam(r *http.Request) string {
	switch src := r.URL.Query().Get("source"); src {
	case "guardian", "zoraxy":
		return src
	}
	return ""
}

func (a *API) handleBlockLogSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, a.store.BlockLogSummarySource(sourceParam(r), 5))
}

func (a *API) handleBlockLogExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	entries := a.store.LogPageSource(sourceParam(r), 0, 0)
	switch r.URL.Query().Get("format") {
	case "json", "":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="guardian-block-log.json"`)
		_ = json.NewEncoder(w).Encode(entries)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="guardian-block-log.csv"`)
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"time", "source", "ip", "fingerprint", "host", "method", "request_uri", "user_agent", "reason", "status"})
		for _, entry := range entries {
			row := []string{
				entry.Time.UTC().Format(time.RFC3339), entry.Source, entry.IP, entry.Fingerprint,
				entry.Host, entry.Method, entry.RequestURI, entry.UserAgent, entry.Reason,
				strconv.Itoa(entry.Status),
			}
			for i := range row {
				row[i] = csvSafe(row[i])
			}
			_ = writer.Write(row)
		}
		writer.Flush()
	default:
		http.Error(w, "format must be json or csv", http.StatusBadRequest)
	}
}

func (a *API) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.store.Snapshot())
	case http.MethodPost:
		var cfg Config
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.store.Update(cfg); err != nil {
			writeUpdateError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleBlockLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	offset := nonNegative(atoiDefault(r.URL.Query().Get("offset"), 0))
	limit := nonNegative(atoiDefault(r.URL.Query().Get("limit"), 0)) // 0 = all
	source := sourceParam(r)
	entries := a.store.LogPageSource(source, offset, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"total":   a.store.LogTotalSource(source),
		"offset":  offset,
		"limit":   limit,
		"entries": entries,
	})
}

// handleBlockLogStream is an SSE endpoint. On open, it pushes a snapshot of
// the most recent N entries (newest first) then streams future entries as
// they arrive. Keepalive comment every 25s.
func (a *API) handleBlockLogStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // hint to upstream proxies
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	ch := a.store.Broadcaster().Subscribe()
	defer a.store.Broadcaster().Unsubscribe(ch)

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case e, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: block\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (a *API) handleTempBans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bans := a.store.TempBansSnapshot()
	type entry struct {
		IP      string `json:"ip"` // an IPv4 address or an IPv6 /64
		Expires string `json:"expires"`
	}
	out := make([]entry, 0, len(bans))
	for ip, exp := range bans {
		out = append(out, entry{IP: ip, Expires: exp.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleTempBansClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ip query param", http.StatusBadRequest)
		return
	}
	a.store.ClearTempBan(ip)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared", "ip": ip})
}

func (a *API) handleFingerprintBans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bans := a.store.FingerprintBansSnapshot()
	type entry struct {
		Fingerprint string `json:"fingerprint"`
		Expires     string `json:"expires"`
	}
	out := make([]entry, 0, len(bans))
	for fp, exp := range bans {
		out = append(out, entry{Fingerprint: fp, Expires: exp.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleFingerprintBansClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fp := r.URL.Query().Get("fingerprint")
	if fp == "" {
		http.Error(w, "missing fingerprint query param", http.StatusBadRequest)
		return
	}
	a.store.ClearFingerprintBan(fp)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared", "fingerprint": fp})
}

// handleImportCF parses a Cloudflare expression and either returns a preview
// of what would be imported (apply=false) or merges into the live config
// (apply=true).
func (a *API) handleImportCF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Expression string `json:"expression"`
		Apply      bool   `json:"apply"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	parsed, err := ParseCloudflareRules(body.Expression)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(),
		})
		return
	}
	if !body.Apply {
		writeJSON(w, http.StatusOK, map[string]any{
			"preview": parsed,
		})
		return
	}
	cfg := a.store.Snapshot()
	stats := MergeCFResult(&cfg, parsed)
	if err := a.store.Update(cfg); err != nil {
		writeUpdateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"applied":  stats,
		"warnings": parsed.Warnings,
	})
}

// handleRecommendedRules previews or merges the defaults shipped with this
// release. Existing custom and host-scoped rules are never overwritten.
func (a *API) handleRecommendedRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Apply bool `json:"apply"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := a.store.Snapshot()
	stats := MergeRecommendedRules(&cfg)
	if !body.Apply {
		writeJSON(w, http.StatusOK, map[string]any{"preview": stats})
		return
	}
	if err := a.store.Update(cfg); err != nil {
		writeUpdateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": stats})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func atoiDefault(s string, d int) int {
	if s == "" {
		return d
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return d
	}
	return n
}

func nonNegative(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
