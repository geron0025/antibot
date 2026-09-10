package aggregate

import (
	"fmt"
	"math"
	"testing"
)

// Below the sparse limit the count is exact: most rows see a few paths,
// and "3" must not come out as "4".
func TestSketchExactWhileSmall(t *testing.T) {
	var s sketch
	for i := 0; i < sparseLimit; i++ {
		s.add(hash(fmt.Sprintf("/p/%d", i)))
		s.add(hash(fmt.Sprintf("/p/%d", i))) // a repeat changes nothing
	}
	if s.Regs != nil {
		t.Fatal("turned into registers before the limit")
	}
	if got := s.estimate(); got != sparseLimit {
		t.Fatalf("estimate %d, want exactly %d", got, sparseLimit)
	}
}

func TestSketchAccuracy(t *testing.T) {
	for _, n := range []int{100, 1000, 10000, 200000} {
		var s sketch
		for i := 0; i < n; i++ {
			s.add(hash(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
		}
		got := float64(s.estimate())
		// Three standard errors of a 1024-register sketch.
		if e := math.Abs(got-float64(n)) / float64(n); e > 0.1 {
			t.Errorf("n=%d: estimate %.0f, error %.1f%%", n, got, e*100)
		}
	}
}

// The ~rest row merges its sketches: one path seen by two folded rows
// is still one path, and summing would call a single scanner a crowd.
func TestSketchMergeIsUnion(t *testing.T) {
	for _, n := range []int{10, 5000} {
		var a, b sketch
		for i := 0; i < n; i++ {
			a.add(hash(fmt.Sprint(i)))
			b.add(hash(fmt.Sprint(i)))
		}
		a.merge(&b)
		got := float64(a.estimate())
		if e := math.Abs(got-float64(n)) / float64(n); e > 0.1 {
			t.Errorf("n=%d: merged estimate %.0f, want about %d", n, got, n)
		}
	}

	// Sparse into dense and dense into sparse.
	var small, big sketch
	small.add(hash("only"))
	for i := 0; i < 1000; i++ {
		big.add(hash(fmt.Sprint(i)))
	}
	small.merge(&big)
	if got := small.estimate(); got < 900 || got > 1100 {
		t.Errorf("sparse merged with dense: %d", got)
	}
}

// The hash must not change between runs: the open window survives a
// restart, and a path hashed differently after it would count twice.
func TestHashIsStable(t *testing.T) {
	if got, want := hash("/catalog"), hash("/catalog"); got != want {
		t.Fatal("the same string hashed differently")
	}
	// Pinned so that a change of the function is a decision, not an
	// accident: it would double every unique count across the restart
	// that brings it.
	if got := fmt.Sprintf("%016x", hash("/catalog")); got != "97f7c1d9b0343a7a" {
		t.Errorf("hash of /catalog is %s", got)
	}
}
