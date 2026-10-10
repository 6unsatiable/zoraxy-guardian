package guardian

import (
	"fmt"
	"net/http"
)

func WriteBlockResponse(w http.ResponseWriter, r *http.Request, d Decision) {
	status := d.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	h := w.Header()
	h.Set("X-Guardian-Reason", d.Reason)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if status == http.StatusTooManyRequests {
		h.Set("Retry-After", "60")
	}
	for k, v := range d.Headers {
		h.Set(k, v)
	}
	w.WriteHeader(status)
	if r != nil && r.Method == http.MethodHead {
		return
	}
	if d.Body != nil {
		_, _ = w.Write(d.Body)
		return
	}
	fmt.Fprintf(w, "%d %s\n", status, http.StatusText(status))
}
