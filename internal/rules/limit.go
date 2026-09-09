package rules

import (
	"context"
	"hash/maphash"
	"sync"
	"time"
)

// Windows is a sliding window in the process's memory.
//
// In memory, and in this very process: a limit of "100 requests per
// minute" across three node replicas means 300 requests per minute. That
// is stated in the README, because otherwise it is discovered only
// through somebody else's complaint.
type Windows struct {
	// Shards remove the contention over a single lock: the limiter is
	// called on every request that fell under a rate rule.
	shards [64]shard
	seed   maphash.Seed

	// MaxKeys bounds the memory. There are as many keys as there are
	// distinct addresses, and addresses can be more numerous than fit.
	MaxKeys int
}

type shard struct {
	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	// stamps are the times of the last requests let through, as a ring.
	// The length never exceeds the rule's limit, so the memory is bounded
	// from above no matter how frequent the client is.
	//
	// The ring grows as needed rather than being allocated for the whole
	// limit at once: otherwise a rule with a limit of a million requests
	// would occupy eight megabytes per address, including those that
	// came by once.
	stamps []int64
	start  int
	length int

	limit  int
	window time.Duration
	last   int64
}

// initialCapacity is what the ring starts with. Eight is enough for the
// overwhelming majority of keys: those that never reach the limit do not
// grow any further.
func initialCapacity(limit int) int {
	if limit < 8 {
		return limit
	}
	return 8
}

// grow doubles the ring without losing the order of the stamps.
func (e *entry) grow() {
	size := len(e.stamps) * 2
	if size > e.limit {
		size = e.limit
	}
	stamps := make([]int64, size)
	for i := 0; i < e.length; i++ {
		stamps[i] = e.stamps[(e.start+i)%len(e.stamps)]
	}
	e.stamps, e.start = stamps, 0
}

// NewWindows creates a limiter. Zero in the maximum number of keys means
// a million — roughly 100 MB at usual limits.
func NewWindows() *Windows {
	w := &Windows{seed: maphash.MakeSeed(), MaxKeys: 1 << 20}
	for i := range w.shards {
		w.shards[i].entries = make(map[string]*entry)
	}
	return w
}

// Exceeded answers whether the limit is used up, and counts the request
// if it is not.
//
// Rejected requests are not counted: otherwise a stream of a thousand
// requests per second would keep the window full forever, and the client
// would stay under the ban even after it stopped being frequent.
func (w *Windows) Exceeded(key string, limit int, window time.Duration, when time.Time) bool {
	if limit <= 0 || window <= 0 {
		return false
	}

	s := &w.shards[maphash.String(w.seed, key)%uint64(len(w.shards))]
	now := when.UnixNano()
	boundary := now - int64(window)

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		// An overflow is no reason to refuse service: we stop counting
		// and keep letting through. The cleanup will give the room back.
		if len(s.entries) >= w.maxKeysPerShard() {
			return false
		}
		e = &entry{stamps: make([]int64, initialCapacity(limit)), limit: limit, window: window}
		s.entries[key] = e
	}

	// The rule may have been changed on the fly: the limit and the window
	// are taken from it, not from the entry.
	if e.limit != limit {
		e.stamps = make([]int64, initialCapacity(limit))
		e.start, e.length, e.limit = 0, 0, limit
	}
	e.window = window
	e.last = now

	// Throw away everything that fell out of the window. The stamps lie
	// in ascending order, so moving the start is enough.
	for e.length > 0 && e.stamps[e.start] <= boundary {
		e.start = (e.start + 1) % len(e.stamps)
		e.length--
	}

	if e.length >= limit {
		return true
	}

	if e.length == len(e.stamps) {
		e.grow()
	}
	e.stamps[(e.start+e.length)%len(e.stamps)] = now
	e.length++
	return false
}

func (w *Windows) maxKeysPerShard() int {
	max := w.MaxKeys
	if max <= 0 {
		max = 1 << 20
	}
	return max/len(w.shards) + 1
}

// Cleanup deletes entries that have not seen a request for a long time.
// Without a cleanup the map grows at the rate new addresses appear and
// never shrinks.
func (w *Windows) Cleanup(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			w.sweep(now)
		}
	}
}

func (w *Windows) sweep(now time.Time) {
	t := now.UnixNano()
	for i := range w.shards {
		s := &w.shards[i]
		s.mu.Lock()
		for key, e := range s.entries {
			if t-e.last > int64(e.window) {
				delete(s.entries, key)
			}
		}
		s.mu.Unlock()
	}
}

// Keys is how many keys are in memory right now. For the service port
// and for tests.
func (w *Windows) Keys() int {
	n := 0
	for i := range w.shards {
		w.shards[i].mu.Lock()
		n += len(w.shards[i].entries)
		w.shards[i].mu.Unlock()
	}
	return n
}
