package guardian

import (
	"fmt"
	"net/http"
)

func WriteBlockResponse(w http.ResponseWriter, d Decision) {
	status := d.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	w.Header().Set("X-Guardian-Reason", d.Reason)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	w.WriteHeader(status)
	fmt.Fprintf(w, "%d %s\n", status, http.StatusText(status))
}
