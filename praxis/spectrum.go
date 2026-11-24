package praxis

import (
	"fmt"
	"math"
)

// Table4G is the paper's exact secret integer range at lambda = 100 (Section 6.2,
// Table 4): the least integer g with g^8 >= 2^405 (~2^50.625).
const Table4G int64 = 1_736_375_024_658_487

// Table4 holds the paper's Table 4 ring, grid, chunk, and secret-integer
// parameters (dR=64, K=71, n=4608, K1=192, K2=12, 6912 cells, J=J'=11, g~2^50.6).
var Table4 = Params{
	DR:     64,
	K:      71,
	K1:     192,
	K2:     12,
	G:      Table4G,
	J:      11,
	JPrime: 11,
	Fast:   true,
}

// Tier describes one stop along the 6-step parameter spectrum from Toy to Table 4.
type Tier struct {
	Index      int    // 1..6
	Name       string // short label
	Subtitle   string // summary of algebraic regime
	SearchBits int    // ~2*log2(g) generic 4-sum search bits (Section 6.2)
	Params     Params
}

// Spectrum spans six logarithmically spaced tiers from Toy (n=8, g=2^20) up to
// Table 4's exact lattice ring and search parameters (n=4608, g~2^50.6).
var Spectrum = [6]Tier{
	{
		Index:      1,
		Name:       "Toy",
		Subtitle:   "pow-of-2 ring · unsplit powers · interval BSGS",
		SearchBits: 40,
		Params:     Toy,
	},
	{
		Index:      2,
		Name:       "Advanced",
		Subtitle:   "Serret n=24 · chunked FFT QAP · sign-FP64",
		SearchBits: 48,
		Params:     Advanced,
	},
	{
		Index:      3,
		Name:       "Medium",
		Subtitle:   "n=96 (144 cells) · g=2^32 · parallel FP64",
		SearchBits: 64,
		Params:     Params{DR: 8, K: 11, K1: 8, K2: 6, G: 1 << 32, J: 4, JPrime: 2, Fast: true},
	},
	{
		Index:      4,
		Name:       "Heavy",
		Subtitle:   "n=384 (576 cells) · g=2^40 · 6x2 chunks",
		SearchBits: 80,
		Params:     Params{DR: 16, K: 23, K1: 16, K2: 12, G: 1 << 40, J: 6, JPrime: 2, Fast: true},
	},
	{
		Index:      5,
		Name:       "Pre-Crypto",
		Subtitle:   "n=1152 (1728 cells) · g=2^45 · 8x4 chunks",
		SearchBits: 90,
		Params:     Params{DR: 32, K: 35, K1: 48, K2: 12, G: 1 << 45, J: 8, JPrime: 4, Fast: true},
	},
	{
		Index:      6,
		Name:       "Table-4",
		Subtitle:   "n=4608 (6912 cells) · g~2^50.6 · J=J'=11",
		SearchBits: 101,
		Params:     Table4,
	},
}

// TierByIndex returns Spectrum[idx-1] for idx in 1..6.
func TierByIndex(idx int) (Tier, error) {
	if idx < 1 || idx > len(Spectrum) {
		return Tier{}, fmt.Errorf("tier must be between 1 and %d", len(Spectrum))
	}
	return Spectrum[idx-1], nil
}

// AdmissibilityReport evaluates Theorem 5.9's structural conditions (P1) and
// Module-SIS matrix aspect ratio on a concrete Public instance.
type AdmissibilityReport struct {
	N, D, NForms   int
	DR, K, Ell     int     // MSIS matrix M in R_q^(K x (Ell+1)), Ell = ceil(N / DR)
	JDelta         int     // J * Delta
	P1NLeD         bool    // n <= D (Theorem 5.9 (P1))
	P1JDeltaBounds bool    // D <= J*Delta <= D + n (Theorem 5.9 (P1))
	MSISWide       bool    // Ell > K (underdetermined ring columns for short MSIS kernel)
	SearchBits     float64 // 2 * log2(g) generic search exponent (Section 6.2)
	MinAdmissibleN int     // PadUnknowns target so both n <= D and Ell > K hold
}

// Admissibility inspects pp against Theorem 5.9 (P1) and MSIS aspect ratio.
func (pp *Public) Admissibility() AdmissibilityReport {
	par := pp.Par
	n := par.NForms()
	ell := (pp.S.N + par.DR - 1) / par.DR
	jDelta := par.JQuo() * pp.Delta
	// Ell >= K + 1 iff ceil(N / DR) >= K + 1, satisfied at N = (K + 1)*DR = n (if DR==1, n; in general K*DR + 1, and n >= K*DR + 1 since DR >= 1).
	minN := n
	if (minN+par.DR-1)/par.DR <= par.K {
		minN = (par.K + 1) * par.DR
	}
	return AdmissibilityReport{
		N:              pp.S.N,
		D:              pp.D,
		NForms:         n,
		DR:             par.DR,
		K:              par.K,
		Ell:            ell,
		JDelta:         jDelta,
		P1NLeD:         n <= pp.D,
		P1JDeltaBounds: pp.D <= jDelta && jDelta <= pp.D+n,
		MSISWide:       ell > par.K,
		SearchBits:     2.0 * math.Log2(float64(par.G)),
		MinAdmissibleN: minN,
	}
}

// FullyAdmissible reports whether both Theorem 5.9 (P1) and Ell > K hold.
func (a AdmissibilityReport) FullyAdmissible() bool {
	return a.P1NLeD && a.P1JDeltaBounds && a.MSISWide
}
