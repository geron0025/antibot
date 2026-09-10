package aggregate

import (
	"math"
	"math/bits"
)

// sketch estimates how many distinct values it has seen: the uniq_paths
// and uniq_addrs of the aggregate.
//
// Two forms. While the values are few, they are kept exactly as a list
// of hashes: most rows see a handful of paths from a handful of
// addresses, and a full HyperLogLog for each of them would multiply the
// memory of a window by a thousand for nothing. Past sparseLimit the
// list turns into registers and stays that way.
//
// Exported fields only because the open window survives a restart as
// JSON; nothing outside the package touches them.
type sketch struct {
	Set  []uint64 `json:"set,omitempty"`
	Regs []byte   `json:"regs,omitempty"`
}

const (
	// precision gives 1024 registers — a kilobyte and a standard error
	// of about three percent. Enough to tell "one address hammering one
	// path" from "fifty addresses walking the catalog", which is all the
	// pair of counters is for.
	precision = 10
	registers = 1 << precision

	// sparseLimit keeps the exact list below the size of the registers.
	sparseLimit = 64
)

func (s *sketch) add(h uint64) {
	if s.Regs != nil {
		s.addDense(h)
		return
	}
	for _, v := range s.Set {
		if v == h {
			return
		}
	}
	s.Set = append(s.Set, h)
	if len(s.Set) > sparseLimit {
		s.densify()
	}
}

func (s *sketch) addDense(h uint64) {
	idx := h >> (64 - precision)
	// The guard bit keeps the count of leading zeros bounded when the
	// remaining bits happen to be all zero.
	rho := byte(bits.LeadingZeros64(h<<precision|1<<(precision-1)) + 1)
	if rho > s.Regs[idx] {
		s.Regs[idx] = rho
	}
}

func (s *sketch) densify() {
	s.Regs = make([]byte, registers)
	for _, v := range s.Set {
		s.addDense(v)
	}
	s.Set = nil
}

// merge folds another sketch in. Used for the ~rest row: the distinct
// paths of the folded rows are merged, not summed, because the same
// path seen by two rows is still one path.
func (s *sketch) merge(o *sketch) {
	if o.Regs != nil && s.Regs == nil {
		s.densify()
	}
	if s.Regs != nil {
		if o.Regs != nil {
			for i, r := range o.Regs {
				if r > s.Regs[i] {
					s.Regs[i] = r
				}
			}
			return
		}
		for _, v := range o.Set {
			s.addDense(v)
		}
		return
	}
	for _, v := range o.Set {
		s.add(v)
	}
}

func (s *sketch) estimate() uint64 {
	if s.Regs == nil {
		return uint64(len(s.Set))
	}

	m := float64(registers)
	sum, zeros := 0.0, 0
	for _, r := range s.Regs {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	alpha := 0.7213 / (1 + 1.079/m)
	e := alpha * m * m / sum

	// Linear counting for the small range, where the raw estimate is
	// biased. No correction for the large range: with 64-bit hashes it
	// would matter only past billions of distinct values.
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros))
	}
	return uint64(math.Round(e))
}

// hash is FNV-1a with a finalizer on top.
//
// Not maphash: its seed changes with every process, and the open window
// survives a restart — the same path hashed differently before and
// after would be counted twice. FNV alone mixes the high bits poorly,
// and the high bits pick the register; the finalizer from MurmurHash3
// spreads them.
func hash(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}
