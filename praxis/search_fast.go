package praxis

import (
	"math"
	"math/big"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
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
	Workers         int
	TableBytes      int64
}

// DecReport records structural, algebraic, and timing telemetry from DecDetailed.
type DecReport struct {
	ExactQAP    bool
	FormsDur    time.Duration
	QAPDur      time.Duration
	PairingsDur time.Duration
	SearchDur   time.Duration
	TotalDur    time.Duration
	Pairings    int
	Search      SearchStats
}

// linearFormCoeffs are fixed non-zero F_p weights projecting C0 in F_{p^6} to F_p
// (Section 6.3: two distinct sign classes collide under the projection with prob 1/p).
var linearFormCoeffs = func() [6]fp.Element {
	raw := [6]uint64{
		0x9e3779b97f4a7c15,
		0xbf58476d1ce4e5b9,
		0x94d049bb133111eb,
		0xd6e8feb86659fd93,
		0xa0761d6478bd642f,
		0xe7037ed1a0b428db,
	}
	var out [6]fp.Element
	for i, v := range raw {
		out[i].SetUint64(v)
	}
	return out
}()

func e6Coords(x *bn254.E6) [6]fp.Element {
	return [6]fp.Element{
		x.B0.A0, x.B0.A1,
		x.B1.A0, x.B1.A1,
		x.B2.A0, x.B2.A1,
	}
}

// projectSignClass maps {V, V^-1} in GT (via its shared F_{p^6} part V.C0) to a
// single F_p element u = sum_{k=0..5} alpha_k * coord_k(V.C0).
func projectSignClass(v *bn254.GT) fp.Element {
	var acc, t fp.Element
	t.Mul(&v.C0.B0.A0, &linearFormCoeffs[0])
	acc.Set(&t)
	t.Mul(&v.C0.B0.A1, &linearFormCoeffs[1])
	acc.Add(&acc, &t)
	t.Mul(&v.C0.B1.A0, &linearFormCoeffs[2])
	acc.Add(&acc, &t)
	t.Mul(&v.C0.B1.A1, &linearFormCoeffs[3])
	acc.Add(&acc, &t)
	t.Mul(&v.C0.B2.A0, &linearFormCoeffs[4])
	acc.Add(&acc, &t)
	t.Mul(&v.C0.B2.A1, &linearFormCoeffs[5])
	acc.Add(&acc, &t)
	return acc
}

// fpElementHash64 hashes all four canonical Montgomery limbs of u in F_p into 64 bits.
func fpElementHash64(u *fp.Element) uint64 {
	h := u[0]*0x9e3779b97f4a7c15 ^ u[1]*0xbf58476d1ce4e5b9 ^ u[2]*0x94d049bb133111eb ^ u[3]*0xd6e8feb86659fd93
	h ^= h >> 31
	h *= 0xa0761d6478bd642f
	return h ^ (h >> 29)
}

func signClassFP64(v *bn254.GT) uint64 {
	u := projectSignClass(v)
	return fpElementHash64(&u)
}

// chebyshevFpRecurrence holds the 6 F_p coefficients c[0..5] of Section 6.3's
// symmetric order-12 recurrence for u_t = ell((V_0 * S^t).C0) in F_p:
//
//	u_{t} = c_0*u_{t-6} + sum_{k=1..5} c_k*(u_{t-6+k} + u_{t-6-k}) - u_{t-12}
//
// requiring exactly 6 F_p multiplications and 11 F_p additions/subtractions per step.
type chebyshevFpRecurrence struct {
	c  [6]fp.Element
	ok bool
}

// deriveChebyshevRecurrence solves the 6x6 F_p linear system expressing T_6(M) in
// terms of {1, T_1(M), ..., T_5(M)}, where M = 2*S.C0 in F_{p^6} and T_k are the
// monic Chebyshev polynomials satisfying T_k(M) * V_m.C0 = V_{m+k}.C0 + V_{m-k}.C0.
func deriveChebyshevRecurrence(step *bn254.GT) chebyshevFpRecurrence {
	var mE6, t0 bn254.E6
	mE6.Double(&step.C0)
	t0.SetOne()
	t0.Double(&t0) // T_0 = 2

	var basis [6]bn254.E6
	basis[0].SetOne()                // B_0 = 1
	basis[1].Set(&mE6)               // T_1 = M
	basis[2].Mul(&mE6, &basis[1])    // M^2
	basis[2].Sub(&basis[2], &t0)     // T_2 = M^2 - 2
	for k := 3; k <= 5; k++ {
		basis[k].Mul(&mE6, &basis[k-1])
		basis[k].Sub(&basis[k], &basis[k-2])
	}
	var t6 bn254.E6
	t6.Mul(&mE6, &basis[5])
	t6.Sub(&t6, &basis[4])

	// Build augmented 6x7 matrix [coord_row(basis[col]) | coord_row(t6)] over F_p.
	var mat [6][7]fp.Element
	rhs := e6Coords(&t6)
	for row := 0; row < 6; row++ {
		mat[row][6] = rhs[row]
	}
	for col := 0; col < 6; col++ {
		coords := e6Coords(&basis[col])
		for row := 0; row < 6; row++ {
			mat[row][col] = coords[row]
		}
	}

	// Gaussian elimination over F_p.
	for piv := 0; piv < 6; piv++ {
		sel := -1
		for r := piv; r < 6; r++ {
			if !mat[r][piv].IsZero() {
				sel = r
				break
			}
		}
		if sel < 0 {
			return chebyshevFpRecurrence{ok: false}
		}
		if sel != piv {
			mat[piv], mat[sel] = mat[sel], mat[piv]
		}
		var inv fp.Element
		inv.Inverse(&mat[piv][piv])
		for c := piv; c < 7; c++ {
			mat[piv][c].Mul(&mat[piv][c], &inv)
		}
		for r := 0; r < 6; r++ {
			if r == piv || mat[r][piv].IsZero() {
				continue
			}
			factor := mat[r][piv]
			for c := piv; c < 7; c++ {
				var prod fp.Element
				prod.Mul(&factor, &mat[piv][c])
				mat[r][c].Sub(&mat[r][c], &prod)
			}
		}
	}

	var out chebyshevFpRecurrence
	out.ok = true
	for i := 0; i < 6; i++ {
		out.c[i] = mat[i][6]
	}
	return out
}

// stepRing advances ring[(t)&15] from ring[(t-12)&15 .. (t-1)&15] in 6 F_p muls + 11 adds/subs.
func (rec *chebyshevFpRecurrence) stepRing(ring *[16]fp.Element, t int64) fp.Element {
	var acc, s, prod fp.Element
	acc.Mul(&rec.c[0], &ring[(t-6)&15])

	s.Add(&ring[(t-5)&15], &ring[(t-7)&15])
	prod.Mul(&rec.c[1], &s)
	acc.Add(&acc, &prod)

	s.Add(&ring[(t-4)&15], &ring[(t-8)&15])
	prod.Mul(&rec.c[2], &s)
	acc.Add(&acc, &prod)

	s.Add(&ring[(t-3)&15], &ring[(t-9)&15])
	prod.Mul(&rec.c[3], &s)
	acc.Add(&acc, &prod)

	s.Add(&ring[(t-2)&15], &ring[(t-10)&15])
	prod.Mul(&rec.c[4], &s)
	acc.Add(&acc, &prod)

	s.Add(&ring[(t-1)&15], &ring[(t-11)&15])
	prod.Mul(&rec.c[5], &s)
	acc.Add(&acc, &prod)

	acc.Sub(&acc, &ring[(t-12)&15])
	ring[t&15] = acc
	return acc
}

// fpSlot is a compact 8-byte pointer-free open-addressed hash table entry.
// Quotienting the low log2(cap) bits into the table index and keeping 32 upper
// tag bits gives up to 57 bits of fingerprint resolution in 8 bytes/slot.
type fpSlot struct {
	tag    uint32
	bPlus1 uint32
}

type fpTable struct {
	slots []fpSlot
	mask  uint64
	shift uint
}

func newFPTable(count int64) fpTable {
	minCap := uint64(max(128, count*2))
	lg := uint(bits.Len64(minCap - 1))
	pow2 := uint64(1) << lg
	sh := lg
	if sh > 32 {
		sh = 32
	}
	return fpTable{
		slots: make([]fpSlot, pow2),
		mask:  pow2 - 1,
		shift: sh,
	}
}

func (t *fpTable) tagOf(fp uint64) uint32 {
	return uint32(fp >> t.shift)
}

func (t *fpTable) insert(fp uint64, b uint32) {
	idx := fp & t.mask
	tag := t.tagOf(fp)
	bp1 := b + 1
	for {
		cur := &t.slots[idx]
		if cur.bPlus1 == 0 {
			cur.tag = tag
			cur.bPlus1 = bp1
			return
		}
		if cur.tag == tag && cur.bPlus1 == bp1 {
			return
		}
		idx = (idx + 1) & t.mask
	}
}

// searchOutwardSignFP64 implements Section 5.2 & 6.3's outward search on GT sign
// classes {V, V^-1} using a compact fingerprint table and the 6-multiplication F_p
// Chebyshev linear recurrence across CPU cores.
func searchOutwardSignFP64(base, target *bn254.GT, bound *big.Int, N int, g int64) (*big.Int, bool, SearchStats) {
	workers := max(1, runtime.NumCPU())
	stats := SearchStats{
		Algorithm: "outward-sign-fp64",
		Bound:     new(big.Int).Set(bound),
		Workers:   workers,
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

	// Balance baby steps and giant steps up to 2^24 (16,777,216 baby steps = 256 MB flat table).
	sigma := float64(g)*math.Sqrt(float64(N+4)/48.0) + 2.0
	bBar := int64(math.Ceil(0.85 * math.Sqrt(sigma)))
	if bBar < 64 {
		bBar = 64
	}
	if bBar > 1<<24 {
		bBar = 1 << 24
	}
	maxB := new(big.Int).Sqrt(new(big.Int).Add(bound, big.NewInt(1)))
	maxB.Add(maxB, big.NewInt(1))
	if maxB.IsInt64() && bBar > maxB.Int64() {
		bBar = max(1, maxB.Int64())
	}

	babyRec := deriveChebyshevRecurrence(base)

	// 1. Compute baby-step fingerprints in parallel chunks via the 6-mul F_p recurrence.
	fps := make([]uint64, bBar)
	computeBabyChunk := func(lo, hi int64) {
		var cur bn254.GT
		cur.Exp(*base, big.NewInt(lo))
		if !babyRec.ok || hi-lo <= 16 {
			for b := lo; b < hi; b++ {
				fps[b] = signClassFP64(&cur)
				cur.Mul(&cur, base)
			}
			return
		}
		var ring [16]fp.Element
		for t := int64(0); t < 12; t++ {
			u := projectSignClass(&cur)
			ring[t] = u
			fps[lo+t] = fpElementHash64(&u)
			cur.Mul(&cur, base)
		}
		for t := int64(12); lo+t < hi; t++ {
			u := babyRec.stepRing(&ring, t)
			fps[lo+t] = fpElementHash64(&u)
		}
	}

	if bBar < 4096 || workers == 1 {
		computeBabyChunk(0, bBar)
	} else {
		var wg sync.WaitGroup
		chunk := (bBar + int64(workers) - 1) / int64(workers)
		for w := 0; w < workers; w++ {
			lo := int64(w) * chunk
			hi := min(bBar, lo+chunk)
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func(lo, hi int64) {
				defer wg.Done()
				computeBabyChunk(lo, hi)
			}(lo, hi)
		}
		wg.Wait()
	}

	tbl := newFPTable(bBar)
	for b, fpVal := range fps {
		tbl.insert(fpVal, uint32(b))
	}
	fps = nil

	stats.BabySteps = bBar
	stats.TableBytes = bBar * 12 // logical (uint64, uint32) entry size (Section 6.3)

	stride := 2*bBar - 1
	strideBig := big.NewInt(stride)
	var stepPos, stepNeg bn254.GT
	stepNeg.Exp(*base, big.NewInt(-stride)) // target * base^(-j*stride) for j > 0
	stepPos.Conjugate(&stepNeg)             // target * base^(+j*stride) for j < 0

	var fpHits, falsePos atomic.Int64

	// verifyShellHit recomputes gStep = target * base^(-signedJ * stride) in GT
	// ONLY on a 57-bit fingerprint match (~1 time per entire decryption!).
	verifyShellHit := func(fpVal uint64, signedJ int64) *big.Int {
		idx := fpVal & tbl.mask
		tag := tbl.tagOf(fpVal)
		var gStep bn254.GT
		gStepComputed := false
		jBig := big.NewInt(signedJ)
		var best, bestAbs *big.Int

		for {
			slot := tbl.slots[idx]
			if slot.bPlus1 == 0 {
				break
			}
			if slot.tag == tag {
				fpHits.Add(1)
				if !gStepComputed {
					exp := new(big.Int).Mul(big.NewInt(-signedJ), strideBig)
					if exp.Sign() >= 0 {
						gStep.Exp(*base, exp)
					} else {
						gStep.Exp(*base, new(big.Int).Neg(exp))
						gStep.Conjugate(&gStep)
					}
					gStep.Mul(target, &gStep)
					gStepComputed = true
				}
				b := int64(slot.bPlus1 - 1)
				var bPow, bConj bn254.GT
				bPow.Exp(*base, big.NewInt(b))
				bConj.Conjugate(&bPow)
				matched := false
				for _, sign := range []int64{1, -1} {
					want := &bPow
					if sign < 0 {
						want = &bConj
					}
					if gStep.Equal(want) {
						matched = true
						t := new(big.Int).Mul(jBig, strideBig)
						t.Add(t, big.NewInt(sign*b))
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
					falsePos.Add(1)
				}
			}
			idx = (idx + 1) & tbl.mask
		}
		return best
	}

	probeFP := func(fpVal uint64, signedJ int64) *big.Int {
		// Fast negative filter before calling verifyShellHit.
		idx := fpVal & tbl.mask
		tag := tbl.tagOf(fpVal)
		for {
			slot := tbl.slots[idx]
			if slot.bPlus1 == 0 {
				return nil
			}
			if slot.tag == tag {
				return verifyShellHit(fpVal, signedJ)
			}
			idx = (idx + 1) & tbl.mask
		}
	}

	// Shell j = 0: covers [-bBar+1, +bBar-1].
	stats.Rounds = 1
	stats.GiantSteps = 1
	if hit := probeFP(signClassFP64(target), 0); hit != nil {
		stats.FingerprintHits = fpHits.Load()
		stats.FalsePositives = falsePos.Load()
		stats.Offset = hit
		return hit, true, stats
	}

	num := new(big.Int).Add(bound, big.NewInt(bBar-1))
	maxJBig, rem := new(big.Int).QuoRem(num, strideBig, new(big.Int))
	if rem.Sign() > 0 {
		maxJBig.Add(maxJBig, big.NewInt(1))
	}
	maxJ := maxJBig.Int64()

	// Small maxJ: sequential shells.
	if maxJ < 2048 || workers == 1 {
		var curPosJ, curNegJ bn254.GT
		curPosJ.Set(target)
		curNegJ.Set(target)
		for j := int64(1); j <= maxJ; j++ {
			curPosJ.Mul(&curPosJ, &stepNeg)
			curNegJ.Mul(&curNegJ, &stepPos)
			stats.GiantSteps += 2
			hp := probeFP(signClassFP64(&curPosJ), j)
			hn := probeFP(signClassFP64(&curNegJ), -j)
			if hp != nil || hn != nil {
				stats.FingerprintHits = fpHits.Load()
				stats.FalsePositives = falsePos.Load()
				best := pickLeastAbs(hp, hn)
				stats.Offset = best
				return best, true, stats
			}
		}
		stats.FingerprintHits = fpHits.Load()
		stats.FalsePositives = falsePos.Load()
		return nil, false, stats
	}

	// Multi-core outward search with Section 6.3's 6-mul F_p Chebyshev recurrence!
	// Note that strideNegW and stridePosW = Conjugate(strideNegW) have the EXACT SAME
	// C0 in F_{p^6}, so one recurrence giantRec drives BOTH +j and -j directions!
	var strideNegW, stridePosW bn254.GT
	strideNegW.Exp(stepNeg, big.NewInt(int64(workers)))
	stridePosW.Conjugate(&strideNegW)
	giantRec := deriveChebyshevRecurrence(&strideNegW)

	type workerState struct {
		ringPos [16]fp.Element
		ringNeg [16]fp.Element
		tIdx    int64 // next ring index to compute (>= 12)
		curPos  bn254.GT
		curNeg  bn254.GT
		seeded  bool
	}
	states := make([]workerState, workers)

	// Seed worker w starting at shell j = w + 1.
	var seedWG sync.WaitGroup
	var initPos0, initNeg0 bn254.GT
	initPos0.Mul(target, &stepNeg)
	initNeg0.Mul(target, &stepPos)
	startPos := make([]bn254.GT, workers)
	startNeg := make([]bn254.GT, workers)
	startPos[0] = initPos0
	startNeg[0] = initNeg0
	for w := 1; w < workers; w++ {
		startPos[w].Mul(&startPos[w-1], &stepNeg)
		startNeg[w].Mul(&startNeg[w-1], &stepPos)
	}
	for w := 0; w < workers; w++ {
		seedWG.Add(1)
		go func(w int) {
			defer seedWG.Done()
			st := &states[w]
			st.curPos = startPos[w]
			st.curNeg = startNeg[w]
			if giantRec.ok {
				cp := st.curPos
				cn := st.curNeg
				for t := int64(0); t < 12; t++ {
					st.ringPos[t] = projectSignClass(&cp)
					st.ringNeg[t] = projectSignClass(&cn)
					cp.Mul(&cp, &strideNegW)
					cn.Mul(&cn, &stridePosW)
				}
				st.tIdx = 0
				st.seeded = true
			}
		}(w)
	}
	seedWG.Wait()

	const shellsPerWorkerBatch = int64(32768)
	batchSpan := int64(workers) * shellsPerWorkerBatch

	for batchStart := int64(1); batchStart <= maxJ; batchStart += batchSpan {
		batchEnd := min(maxJ, batchStart+batchSpan-1)
		var foundMinShell atomic.Int64
		foundMinShell.Store(batchEnd + 1)

		hits := make([]*big.Int, workers)
		var stepsDone atomic.Int64
		var wg sync.WaitGroup

		for w := 0; w < workers; w++ {
			firstJ := batchStart + int64(w)
			if firstJ > batchEnd {
				break
			}
			wg.Add(1)
			go func(w int, startJ int64) {
				defer wg.Done()
				st := &states[w]
				var localSteps int64
				var workerBest *big.Int

				for j := startJ; j <= batchEnd; j += int64(workers) {
					if j > foundMinShell.Load() {
						break
					}
					localSteps += 2
					var fpPos, fpNeg uint64
					if st.seeded {
						var uPos, uNeg fp.Element
						if st.tIdx < 12 {
							uPos = st.ringPos[st.tIdx]
							uNeg = st.ringNeg[st.tIdx]
						} else {
							uPos = giantRec.stepRing(&st.ringPos, st.tIdx)
							uNeg = giantRec.stepRing(&st.ringNeg, st.tIdx)
						}
						st.tIdx++
						fpPos = fpElementHash64(&uPos)
						fpNeg = fpElementHash64(&uNeg)
					} else {
						fpPos = signClassFP64(&st.curPos)
						fpNeg = signClassFP64(&st.curNeg)
						st.curPos.Mul(&st.curPos, &strideNegW)
						st.curNeg.Mul(&st.curNeg, &stridePosW)
					}

					hp := probeFP(fpPos, j)
					hn := probeFP(fpNeg, -j)
					if hp != nil || hn != nil {
						cand := pickLeastAbs(hp, hn)
						workerBest = pickLeastAbs(workerBest, cand)
						for {
							curMin := foundMinShell.Load()
							if j >= curMin || foundMinShell.CompareAndSwap(curMin, j) {
								break
							}
						}
						break
					}
				}
				hits[w] = workerBest
				stepsDone.Add(localSteps)
			}(w, firstJ)
		}
		wg.Wait()
		stats.GiantSteps += stepsDone.Load()

		var overallBest *big.Int
		for _, h := range hits {
			overallBest = pickLeastAbs(overallBest, h)
		}
		if overallBest != nil {
			stats.FingerprintHits = fpHits.Load()
			stats.FalsePositives = falsePos.Load()
			stats.Offset = overallBest
			return overallBest, true, stats
		}
	}

	stats.FingerprintHits = fpHits.Load()
	stats.FalsePositives = falsePos.Load()
	return nil, false, stats
}

func pickLeastAbs(a, b *big.Int) *big.Int {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	absA := new(big.Int).Abs(a)
	absB := new(big.Int).Abs(b)
	if absB.Cmp(absA) < 0 {
		return b
	}
	return a
}
