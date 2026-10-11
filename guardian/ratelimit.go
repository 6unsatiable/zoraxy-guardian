package guardian

import (
	"sort"
	"sync"
	"time"
)

const (
	// Buckets idle for this long are evicted on the next sweep.
	bucketIdleTTL = 10 * time.Minute
	// Hard cap on the bucket map; if we hit this, the oldest are evicted.
	maxBuckets = 50000
	// How often the background sweep runs. Cheap loop — just walks the map.
	sweepInterval = 1 * time.Minute
)

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	rate    float64 // tokens per second
	burst   float64
	mu      sync.Mutex
	buckets map[string]*bucket

	stop chan struct{}
}

func newRateLimiter(perMinute, burst int) *rateLimiter {
	if perMinute < 1 {
		perMinute = 1
	}
	if burst < 1 {
		burst = 1
	}
	rl := &rateLimiter{
		rate:    float64(perMinute) / 60.0,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		stop:    make(chan struct{}),
	}
	go rl.sweepLoop()
	return rl
}

func (rl *rateLimiter) Stop() {
	select {
	case <-rl.stop:
	default:
		close(rl.stop)
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		if len(rl.buckets) >= maxBuckets {
			rl.evictOldestLocked(now)
		}
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = floatMin(rl.burst, b.tokens+elapsed*rl.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

func (rl *rateLimiter) sweepLoop() {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case now := <-t.C:
			rl.sweep(now)
		}
	}
}

func (rl *rateLimiter) sweep(now time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, b := range rl.buckets {
		if now.Sub(b.last) > bucketIdleTTL {
			delete(rl.buckets, k)
		}
	}
}

// evictOldestLocked drops ~1% of the map by last-access age. Caller holds mu.
func (rl *rateLimiter) evictOldestLocked(now time.Time) {
	target := maxBuckets / 100
	if target < 1 {
		target = 1
	}
	type pair struct {
		k   string
		age time.Duration
	}
	candidates := make([]pair, 0, len(rl.buckets))
	for k, b := range rl.buckets {
		candidates = append(candidates, pair{k, now.Sub(b.last)})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].age > candidates[j].age })
	for i := 0; i < target && i < len(candidates); i++ {
		delete(rl.buckets, candidates[i].k)
	}
}

func floatMin(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
