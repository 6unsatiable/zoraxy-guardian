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

// pathWindow remembers when each distinct path was last requested, so the
// window rolls: a path counts until `window` after its latest hit.
type pathWindow struct {
	seen map[uint64]time.Time
}

type behaviorTracker struct {
	mu   sync.Mutex
	keys map[string]*pathWindow
}

func newBehaviorTracker() *behaviorTracker {
	return &behaviorTracker{keys: make(map[string]*pathWindow)}
}

// note records a request path for key and reports whether the key has now
// requested more than max distinct paths within the rolling window.
func (t *behaviorTracker) note(key, path string, max int, window time.Duration, now time.Time) bool {
	h := fnv.New64a()
	h.Write([]byte(path))
	sum := h.Sum64()
	t.mu.Lock()
	defer t.mu.Unlock()
	w := t.keys[key]
	if w == nil {
		if len(t.keys) >= maxTrackedKeys {
			t.evict(now, window)
		}
		w = &pathWindow{seen: make(map[uint64]time.Time)}
		t.keys[key] = w
	}
	w.seen[sum] = now
	live := 0
	for k, at := range w.seen {
		if now.Sub(at) > window {
			delete(w.seen, k)
			continue
		}
		live++
	}
	if live > max {
		delete(t.keys, key)
		return true
	}
	return false
}

// evict makes room for a new key: idle ones first, then a tenth of the rest.
// Dropping tracked keys is preferred over refusing to track new ones, which
// would let a flood of throwaway addresses blind the tracker.
func (t *behaviorTracker) evict(now time.Time, window time.Duration) {
	for k, v := range t.keys {
		idle := true
		for _, at := range v.seen {
			if now.Sub(at) <= window {
				idle = false
				break
			}
		}
		if idle {
			delete(t.keys, k)
		}
	}
	drop := len(t.keys) - maxTrackedKeys + maxTrackedKeys/10
	for k := range t.keys {
		if drop <= 0 {
			break
		}
		delete(t.keys, k)
		drop--
	}
}
