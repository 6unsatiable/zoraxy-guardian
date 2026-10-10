package guardian

import (
	"hash/fnv"
	"sync"
	"time"
)

// Behavior bans clients that crawl a browser-facing site: a person clicks
// through a handful of pages a minute, a scraper walks hundreds. Only
// requests without a challenge cookie or credentials are counted, so a
// logged-in or verified browser is never affected.
type Behavior struct {
	Enabled       bool `json:"enabled"`
	MaxPaths      int  `json:"max_paths"`      // distinct paths per window
	WindowSeconds int  `json:"window_seconds"` // rolling window
	BanSeconds    int  `json:"ban_seconds"`
}

type pathWindow struct {
	start time.Time
	paths map[uint64]struct{}
}

type behaviorTracker struct {
	mu   sync.Mutex
	keys map[string]*pathWindow
}

func newBehaviorTracker() *behaviorTracker {
	return &behaviorTracker{keys: make(map[string]*pathWindow)}
}

// note records a request path for key and reports whether the key has now
// requested more than max distinct paths within window.
func (t *behaviorTracker) note(key, path string, max int, window time.Duration, now time.Time) bool {
	h := fnv.New64a()
	h.Write([]byte(path))
	sum := h.Sum64()
	t.mu.Lock()
	defer t.mu.Unlock()
	w := t.keys[key]
	if w == nil || now.Sub(w.start) > window {
		if w == nil && len(t.keys) >= maxTrackedKeys {
			for k, v := range t.keys {
				if now.Sub(v.start) > window {
					delete(t.keys, k)
				}
			}
			if len(t.keys) >= maxTrackedKeys {
				return false
			}
		}
		w = &pathWindow{start: now, paths: make(map[uint64]struct{})}
		t.keys[key] = w
	}
	w.paths[sum] = struct{}{}
	if len(w.paths) > max {
		delete(t.keys, key)
		return true
	}
	return false
}
