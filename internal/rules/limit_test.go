package rules

import (
	"fmt"
	"hash/maphash"
	"sync"
	"testing"
	"time"
)

func TestSlidingWindow(t *testing.T) {
	w := NewWindows()
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	window := time.Minute

	// The first three pass, the fourth hits the limit.
	for i := 0; i < 3; i++ {
		if w.Exceeded("k", 3, window, start.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("request %d hit the limit ahead of time", i+1)
		}
	}
	if !w.Exceeded("k", 3, window, start.Add(3*time.Second)) {
		t.Fatal("the fourth request must hit the limit")
	}

	// The window slides: by second 61 the stamps of seconds zero and one
	// have left the window, and exactly as many slots — two — freed up.
	for i := 0; i < 2; i++ {
		if w.Exceeded("k", 3, window, start.Add(61*time.Second)) {
			t.Errorf("request %d must pass after two stamps left the window", i+1)
		}
	}
	if !w.Exceeded("k", 3, window, start.Add(61*time.Second)) {
		t.Error("the third right after them must not")
	}
}

// Rejected requests are not counted: otherwise a client that keeps being
// frequent would stay under the ban even after it stopped.
func TestAStreamDoesNotProlongTheBan(t *testing.T) {
	w := NewWindows()
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	// A second of a thousand-request stream.
	for i := 0; i < 1000; i++ {
		w.Exceeded("k", 2, time.Minute, start.Add(time.Duration(i)*time.Millisecond))
	}
	// A minute after the last request let through — allowed again.
	if w.Exceeded("k", 2, time.Minute, start.Add(61*time.Second)) {
		t.Error("the client stayed under the ban after it stopped being frequent")
	}
}

func TestKeysAreSeparate(t *testing.T) {
	w := NewWindows()
	now := time.Now()
	if w.Exceeded("a", 1, time.Minute, now) {
		t.Fatal("the first request under key a")
	}
	if w.Exceeded("b", 1, time.Minute, now) {
		t.Error("key b is counted together with a")
	}
	if !w.Exceeded("a", 1, time.Minute, now) {
		t.Error("the second request under a must hit the limit")
	}
}

// The limit and the window are taken from the rule on every request: the
// rule may have been changed on the fly, and the old count makes no sense
// after that.
func TestChangingTheLimitResetsTheCount(t *testing.T) {
	w := NewWindows()
	now := time.Now()
	w.Exceeded("k", 1, time.Minute, now)
	if w.Exceeded("k", 5, time.Minute, now) {
		t.Error("after the limit is raised the request must pass")
	}
}

func TestCleanupFreesMemory(t *testing.T) {
	w := NewWindows()
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		w.Exceeded(fmt.Sprintf("k%d", i), 10, time.Minute, start)
	}
	if n := w.Keys(); n != 100 {
		t.Fatalf("%d keys, want 100", n)
	}
	w.sweep(start.Add(30 * time.Second))
	if n := w.Keys(); n != 100 {
		t.Errorf("live keys were swept away: %d left", n)
	}
	w.sweep(start.Add(2 * time.Minute))
	if n := w.Keys(); n != 0 {
		t.Errorf("after the window no keys must be left, %d left", n)
	}
}

// A map overflow must not turn into a denial of service: we stop
// counting and keep letting through.
func TestOverflowDoesNotBlock(t *testing.T) {
	w := NewWindows()
	w.MaxKeys = 64
	now := time.Now()
	for i := 0; i < 5000; i++ {
		if w.Exceeded(fmt.Sprintf("k%d", i), 1, time.Minute, now) {
			t.Fatalf("the new key %d hit the limit on its very first request", i)
		}
	}
	if w.Keys() > 64+len(w.shards) {
		t.Errorf("the map grew past the limit: %d keys", w.Keys())
	}
}

func TestLimiterUnderRace(t *testing.T) {
	w := NewWindows()
	now := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				w.Exceeded(fmt.Sprintf("k%d", j%8), 10, time.Minute, now)
			}
		}(i)
	}
	wg.Wait()
}

func BenchmarkExceeded(b *testing.B) {
	w := NewWindows()
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Exceeded("203.0.113.7", 1000000, time.Minute, now)
	}
}

// The ring grows as needed. A rule with a large limit must not occupy
// memory for every address that came by once: the fuzzer found exactly
// this — a single request under a rule with a limit of two billion
// allocated sixteen gigabytes and took eight milliseconds.
func TestALargeLimitDoesNotOccupyMemory(t *testing.T) {
	w := NewWindows()
	now := time.Now()
	w.Exceeded("k", MaxLimit, time.Minute, now)

	s := &w.shards[maphash.String(w.seed, "k")%uint64(len(w.shards))]
	s.mu.Lock()
	capacity := len(s.entries["k"].stamps)
	s.mu.Unlock()

	if capacity > 8 {
		t.Errorf("a ring of %d stamps was allocated for a single request", capacity)
	}
}

// A grown ring must not lose the order of the stamps, otherwise trimming
// by the window boundary starts throwing away the wrong ones.
func TestRingGrowthKeepsTheOrder(t *testing.T) {
	w := NewWindows()
	start := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	const limit = 100

	// Fill it with a margin so that the ring grows several times, and
	// turn it over while doing so: some stamps must leave the window.
	for i := 0; i < 250; i++ {
		w.Exceeded("k", limit, time.Minute, start.Add(time.Duration(i)*time.Second))
	}

	// By second 250 exactly 60 stamps fit into the minute window — one
	// per second — which means there is room.
	if w.Exceeded("k", limit, time.Minute, start.Add(250*time.Second)) {
		t.Error("the limit fired where the window holds fewer than a hundred stamps")
	}
}
