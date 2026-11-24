package praxis

import (
	"math"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// EncReport records structural and timing telemetry from EncDetailed.
type EncReport struct {
	SetupDur, EncDur time.Duration
	G1, G2           int
	Bytes            int
	J, Delta         int
	JPrime, DeltaP   int
	Forms, Cells     int
}

// SearchStats records telemetry from the discrete-log search in DecDetailed.
type SearchStats struct {
	Algorithm       string
	Center          *big.Int
	Offset          *big.Int
	SecretSum       *big.Int
	Bound           *big.Int
	BabySteps       int64
	GiantSteps      int64
	FingerprintHits int64
	FalsePositives  int64
	Rounds          int
	TableBytes      int64
}

// DecReport records structural, algebraic, and timing telemetry from DecDetailed.
type DecReport struct {
	ExactQAP     bool
	FormsDur     time.Duration
	QAPDur       time.Duration
	PairingsDur  time.Duration
	SearchDur    time.Duration
	TotalDur     time.Duration
	Pairings     int
	Search       SearchStats
}

// fpMultipliers are fixed odd 64-bit universal-hash multipliers for mixing the
// 24 canonical limbs of V.C0 (the F_{p^6} coordinate shared by V and V^-1 in GT).
var fpMultipliers = [24]uint64{
	0x9e3779b97f4a7c15, 0xbf58476d1ce4e5b9, 0x94d049bb133111eb, 0xd6e8feb86659fd93,
	0xa0761d6478bd642f, 0xe7037ed1a0b428db, 0x8ebc6af09c88c6e3, 0x589965cc75374cc3,
	0x1d8e4e27c47d124f, 0xebedeed9d8a3f92d, 0x2545f4914f6cdd1d, 0x9e6c63d0676a9a99,
	0x6c62272e07bb0143, 0x6295c58d72b5f277, 0xb76d53fb6a1c8e45, 0x3b8c9f51d7e2a4b1,
	0xc4ceb9fe1a85ec53, 0xff51afd7ed558ccd, 0x85ebca6b27d4eb2f, 0x165667b19e3779f9,
	0xd8163841f3376597, 0x4cf5ad432745937f, 0x7fb5d329728ea185, 0x81dadef4bc2dd44d,
}

// signClassFP64 computes a 64-bit fingerprint of the sign class {V, V^-1} in GT.
// For unitary elements of BN254's GT, V^-1 = Conjugate(V) = C0 - C1*w, so V and
// V^-1 have identical C0 in F_{p^6} (Section 5.2, "Sign classes").
func signClassFP64(v *bn254.GT) uint64 {
	elems := [6][4]uint64{
		v.C0.B0.A0, v.C0.B0.A1,
		v.C0.B1.A0, v.C0.B1.A1,
		v.C0.B2.A0, v.C0.B2.A1,
	}
	var h uint64 = 0x6a09e667f3bcc909
	idx := 0
	for e := 0; e < 6; e++ {
		for limb := 0; limb < 4; limb++ {
			x := elems[e][limb]
			h ^= x * fpMultipliers[idx]
			h = (h << 29) | (h >> 35)
			h *= 0x9e3779b97f4a7c15
			idx++
		}
	}
	return h ^ (h >> 32)
}

// searchOutwardSignFP64 implements Section 5.2's outward search on GT sign
// classes {V, V^-1} using a compact table of 64-bit F_{p^6} fingerprints.
// Each baby step 0 <= b < bBar covers both +b and -b at once, and giant steps
// target * base^(-j*(2*bBar-1)) for j = 0, +-1, +-2, ... search outward from 0,
// returning the integer t of least absolute value with |t| <= bound.
func searchOutwardSignFP64(base, target *bn254.GT, bound *big.Int, N int, g int64) (*big.Int, bool, SearchStats) {
	stats := SearchStats{
		Algorithm: "outward-sign-fp64",
		Bound:     new(big.Int).Set(bound),
	}
	if bound.Sign() < 0 {
		return nil, false, stats
	}
	if target.IsOne() {
		stats.Offset = new(big.Int)
		stats.Rounds = 1
		return new(big.Int), true, stats
	}
	if base.IsOne() {
		return nil, false, stats
	}

	// Choose baby-step count bBar ~ ceil(1.5 * sqrt(sigma)), where sigma = g*sqrt((N+4)/48)
	// is the Lemma 5.5 standard deviation of r(w) - c_w, clamped to [64, min(sqrt(bound+1), 1<<18)].
	sigma := float64(g)*math.Sqrt(float64(N+4)/48.0) + 2.0
	bBar := int64(math.Ceil(1.5 * math.Sqrt(sigma)))
	if bBar < 64 {
		bBar = 64
	}
	if bBar > 1<<18 {
		bBar = 1 << 18
	}
	maxB := new(big.Int).Sqrt(new(big.Int).Add(bound, big.NewInt(1)))
	maxB.Add(maxB, big.NewInt(1))
	if maxB.IsInt64() && bBar > maxB.Int64() {
		bBar = max(1, maxB.Int64())
	}

	// Build fixed baby-step table of 64-bit fingerprints of base^b (0 <= b < bBar).
	// Storing (uint64 -> int32) takes 12 logical bytes per baby step (Section 6.3).
	primary := make(map[uint64]int32, bBar)
	var collisions map[uint64][]int32
	var cur bn254.GT
	cur.SetOne()
	for b := int64(0); b < bBar; b++ {
		fp := signClassFP64(&cur)
		if prev, exists := primary[fp]; !exists {
			primary[fp] = int32(b)
		} else if int64(prev) != b {
			if collisions == nil {
				collisions = make(map[uint64][]int32)
			}
			collisions[fp] = append(collisions[fp], int32(b))
		}
		cur.Mul(&cur, base)
	}
	stats.BabySteps = bBar
	stats.TableBytes = bBar * 12

	// Step width S = 2*bBar - 1 covers [-(bBar-1), +(bBar-1)] at j = 0 and tiles Z outward.
	stride := 2*bBar - 1
	strideBig := big.NewInt(stride)
	var stepPos, stepNeg bn254.GT
	// cur currently holds base^bBar; base^(2*bBar-1) = (base^bBar)^2 * base^-1.
	var baseInv bn254.GT
	baseInv.Conjugate(base) // unitary inverse in GT
	stepPos.Square(&cur)
	stepPos.Mul(&stepPos, &baseInv) // base^(2*bBar - 1)
	stepNeg.Conjugate(&stepPos)     // base^-(2*bBar - 1)

	// Verify a giant-step candidate gStep = target * base^(-j*stride) against any
	// matching baby-step fingerprint: checks both +b (t = j*stride + b) and -b
	// (t = j*stride - b) in full in GT.
	checkCandidate := func(gStep *bn254.GT, j *big.Int) *big.Int {
		fp := signClassFP64(gStep)
		first, ok := primary[fp]
		if !ok {
			return nil
		}
		var best, bestAbs *big.Int
		tryB := func(b int32) {
			stats.FingerprintHits++
			var bPow, bConj bn254.GT
			bPow.Exp(*base, big.NewInt(int64(b)))
			bConj.Conjugate(&bPow)
			matched := false
			for _, sign := range []int64{1, -1} {
				want := &bPow
				if sign < 0 {
					want = &bConj
				}
				if gStep.Equal(want) {
					matched = true
					t := new(big.Int).Mul(j, strideBig)
					t.Add(t, big.NewInt(sign*int64(b)))
					absT := new(big.Int).Abs(t)
					if absT.Cmp(bound) <= 0 {
						if best == nil || absT.Cmp(bestAbs) < 0 {
							best = t
							bestAbs = absT
						}
					}
				}
			}
			if !matched {
				stats.FalsePositives++
			}
		}
		tryB(first)
		for _, extra := range collisions[fp] {
			tryB(extra)
		}
		return best
	}

	// Shell j = 0: |t| <= bBar - 1.
	stats.GiantSteps++
	stats.Rounds = 1
	if hit := checkCandidate(target, big.NewInt(0)); hit != nil {
		stats.Offset = hit
		return hit, true, stats
	}

	// Outward shells j = 1, 2, ..., jMax, where jMax = ceil((bound + bBar - 1) / stride).
	num := new(big.Int).Add(bound, big.NewInt(bBar-1))
	num.Add(num, big.NewInt(stride-1))
	jMax := new(big.Int).Div(num, strideBig)

	curPos := *target // tracks j = +1, +2, ... via * stepNeg
	curNeg := *target // tracks j = -1, -2, ... via * stepPos
	jBig := new(big.Int)
	negJBig := new(big.Int)
	oneBig := big.NewInt(1)
	for jBig.SetInt64(1); jBig.Cmp(jMax) <= 0; jBig.Add(jBig, oneBig) {
		stats.Rounds++
		curPos.Mul(&curPos, &stepNeg)
		curNeg.Mul(&curNeg, &stepPos)
		stats.GiantSteps += 2

		hitPos := checkCandidate(&curPos, jBig)
		negJBig.Neg(jBig)
		hitNeg := checkCandidate(&curNeg, negJBig)
		if hitPos != nil || hitNeg != nil {
			best := hitPos
			if best == nil || (hitNeg != nil && new(big.Int).Abs(hitNeg).Cmp(new(big.Int).Abs(best)) < 0) {
				best = hitNeg
			}
			stats.Offset = best
			return best, true, stats
		}
	}
	return nil, false, stats
}
