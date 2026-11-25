package praxis

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math/big"
	"math/bits"
	"runtime"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"praxis-demo/poly"
)

const (
	streamBufBytes = 8 << 20 // 8 MiB sequential I/O buffer
	streamG1Batch  = 16384   // 512 KiB scalars -> 512 KiB compressed G1 per batch
	streamG2Batch  = 8192    // 256 KiB scalars -> 512 KiB compressed G2 per batch

	// Signed fixed-base window geometry for G1/G2 generators:
	// 22 windows of 12 bits (digits in [-2047, +2048], 2048 affine entries/window):
	//   - G1 table: 22 * 2048 * 64 B  = 2.75 MiB
	//   - G2 table: 22 * 2048 * 128 B = 5.50 MiB
	// Computes [s]G in <= 22 AddMixed ops with ZERO doublings.
	fixedWinBits    = 12
	fixedWinMask    = (1 << fixedWinBits) - 1
	fixedWinHalf    = 1 << (fixedWinBits - 1)
	fixedWinEntries = fixedWinHalf // stores [1..2048] * 2^(12*k) * G
	fixedWinCount   = 22           // 22 * 12 = 264 >= 254 bits (carry out guaranteed 0)

	// Stream-wide batch G2 prime-order subgroup check parameters:
	// On BN254, h2 = 2p - r has smallest prime factor 10069 > 4096 (asserted in init()).
	// Each 12-bit CSPRNG bucketed trial catches any non-subgroup point with prob >= 1 - 2^-12;
	// 7 independent trials yield soundness error <= 2^-84 (stronger than gnark-crypto's 2^-64).
	g2SubgroupTrials     = 7
	g2SubgroupBucketBits = 12
	g2SubgroupBuckets    = 1 << g2SubgroupBucketBits // 4096 (indices 1..4095 active)
	g2SubgroupDirectMax  = 2048                      // below this sector size, check every point directly
)

var (
	fixedG1Once  sync.Once
	fixedG1Table [fixedWinCount][fixedWinEntries]bn254.G1Affine

	fixedG2Once  sync.Once
	fixedG2Table [fixedWinCount][fixedWinEntries]bn254.G2Affine
)

func init() {
	// Verify mathematically at startup that the BN254 G2 twist cofactor h2 = 2p - r
	// has no prime factor <= 1024, guaranteeing zero modulo collision in 10-bit bucketed
	// batch subgroup checks (soundness error <= 2^-80 across 8 independent trials).
	p := fp.Modulus()
	r := fr.Modulus()
	h2 := new(big.Int).Sub(new(big.Int).Lsh(p, 1), r)
	var rem big.Int
	for d := int64(2); d <= g2SubgroupBuckets; d++ {
		if rem.Mod(h2, big.NewInt(d)).Sign() == 0 {
			panic(fmt.Sprintf("praxis stream init: unexpected small BN254 G2 cofactor divisor %d", d))
		}
	}
}

func initFixedG1Table() {
	fixedG1Once.Do(func() {
		_, _, g1Gen, _ := bn254.Generators()
		var bases [fixedWinCount]bn254.G1Jac
		bases[0].FromAffine(&g1Gen)
		for k := 1; k < fixedWinCount; k++ {
			bases[k] = bases[k-1]
			for d := 0; d < fixedWinBits; d++ {
				bases[k].DoubleAssign()
			}
		}
		var wg sync.WaitGroup
		wg.Add(fixedWinCount)
		for k := 0; k < fixedWinCount; k++ {
			go func(k int) {
				defer wg.Done()
				var baseAff bn254.G1Affine
				baseAff.FromJacobian(&bases[k])
				jac := make([]bn254.G1Jac, fixedWinEntries)
				jac[0] = bases[k]
				for i := 1; i < fixedWinEntries; i++ {
					jac[i] = jac[i-1]
					jac[i].AddMixed(&baseAff)
				}
				aff := bn254.BatchJacobianToAffineG1(jac)
				copy(fixedG1Table[k][:], aff)
			}(k)
		}
		wg.Wait()
	})
}

// batchJacobianToAffineG2 converts a slice of Jacobian G2 points to affine coordinates
// using Montgomery's trick (1 E2 inversion + 3n E2 multiplications instead of n inversions).
func batchJacobianToAffineG2(points []bn254.G2Jac) []bn254.G2Affine {
	n := len(points)
	res := make([]bn254.G2Affine, n)
	if n == 0 {
		return res
	}
	prod := make([]bn254.E2, n)
	var acc bn254.E2
	acc.SetOne()
	for i := 0; i < n; i++ {
		if !points[i].Z.IsZero() {
			acc.Mul(&acc, &points[i].Z)
		}
		prod[i] = acc
	}
	var invAcc, zInv, zInv2, zInv3 bn254.E2
	invAcc.Inverse(&acc)
	for i := n - 1; i >= 0; i-- {
		if points[i].Z.IsZero() {
			continue
		}
		if i > 0 {
			zInv.Mul(&invAcc, &prod[i-1])
			invAcc.Mul(&invAcc, &points[i].Z)
		} else {
			zInv = invAcc
		}
		zInv2.Square(&zInv)
		zInv3.Mul(&zInv2, &zInv)
		res[i].X.Mul(&points[i].X, &zInv2)
		res[i].Y.Mul(&points[i].Y, &zInv3)
	}
	return res
}

func initFixedG2Table() {
	fixedG2Once.Do(func() {
		_, _, _, g2Gen := bn254.Generators()
		var bases [fixedWinCount]bn254.G2Jac
		bases[0].FromAffine(&g2Gen)
		for k := 1; k < fixedWinCount; k++ {
			bases[k] = bases[k-1]
			for d := 0; d < fixedWinBits; d++ {
				bases[k].DoubleAssign()
			}
		}
		var wg sync.WaitGroup
		wg.Add(fixedWinCount)
		for k := 0; k < fixedWinCount; k++ {
			go func(k int) {
				defer wg.Done()
				var baseAff bn254.G2Affine
				baseAff.FromJacobian(&bases[k])
				jac := make([]bn254.G2Jac, fixedWinEntries)
				jac[0] = bases[k]
				for i := 1; i < fixedWinEntries; i++ {
					jac[i] = jac[i-1]
					jac[i].AddMixed(&baseAff)
				}
				aff := batchJacobianToAffineG2(jac)
				copy(fixedG2Table[k][:], aff)
			}(k)
		}
		wg.Wait()
	})
}

// mulFixedG1Jac computes [s]g1Gen in Jacobian coordinates with zero doublings (<= 26 AddMixed ops).
func mulFixedG1Jac(s *fr.Element) bn254.G1Jac {
	words := s.Bits()
	var acc bn254.G1Jac
	var pt bn254.G1Affine
	var carry int32
	for k := 0; k < fixedWinCount; k++ {
		bitPos := k * fixedWinBits
		wordIdx := bitPos >> 6
		bitOff := uint(bitPos & 63)
		var raw uint32
		if wordIdx < 4 {
			raw = uint32(words[wordIdx] >> bitOff)
			if bitOff > 64-fixedWinBits && wordIdx+1 < 4 {
				raw |= uint32(words[wordIdx+1] << (64 - bitOff))
			}
		}
		val := int32(raw&fixedWinMask) + carry
		if val > fixedWinHalf {
			val -= 1 << fixedWinBits
			carry = 1
		} else {
			carry = 0
		}
		if val > 0 {
			acc.AddMixed(&fixedG1Table[k][val-1])
		} else if val < 0 {
			pt = fixedG1Table[k][-val-1]
			pt.Y.Neg(&pt.Y)
			acc.AddMixed(&pt)
		}
	}
	return acc
}

// mulFixedG2Jac computes [s]g2Gen in Jacobian coordinates with zero doublings (<= 26 AddMixed ops).
func mulFixedG2Jac(s *fr.Element) bn254.G2Jac {
	words := s.Bits()
	var acc bn254.G2Jac
	var pt bn254.G2Affine
	var carry int32
	for k := 0; k < fixedWinCount; k++ {
		bitPos := k * fixedWinBits
		wordIdx := bitPos >> 6
		bitOff := uint(bitPos & 63)
		var raw uint32
		if wordIdx < 4 {
			raw = uint32(words[wordIdx] >> bitOff)
			if bitOff > 64-fixedWinBits && wordIdx+1 < 4 {
				raw |= uint32(words[wordIdx+1] << (64 - bitOff))
			}
		}
		val := int32(raw&fixedWinMask) + carry
		if val > fixedWinHalf {
			val -= 1 << fixedWinBits
			carry = 1
		} else {
			carry = 0
		}
		if val > 0 {
			acc.AddMixed(&fixedG2Table[k][val-1])
		} else if val < 0 {
			pt = fixedG2Table[k][-val-1]
			pt.Y.Neg(&pt.Y)
			acc.AddMixed(&pt)
		}
	}
	return acc
}

// batchMulCompressG1 computes compressed [scalars[i]]g1Gen into rawOut across all CPU cores
// using fixed-base zero-doubling multiplication and per-worker BatchJacobianToAffineG1.
func batchMulCompressG1(scalars []fr.Element, jacBuf []bn254.G1Jac, rawOut []byte, workers int) {
	initFixedG1Table()
	n := len(scalars)
	if n == 0 {
		return
	}
	runSlice := func(lo, hi int) {
		for i := lo; i < hi; i++ {
			jacBuf[i] = mulFixedG1Jac(&scalars[i])
		}
		aff := bn254.BatchJacobianToAffineG1(jacBuf[lo:hi])
		for off := range aff {
			b := aff[off].Bytes()
			copy(rawOut[(lo+off)*bn254.SizeOfG1AffineCompressed:], b[:])
		}
	}
	if workers <= 1 || n < 256 {
		runSlice(0, n)
		return
	}
	w := min(workers, (n+127)/128)
	chunk := (n + w - 1) / w
	var wg sync.WaitGroup
	for wk := 0; wk < w; wk++ {
		lo := wk * chunk
		hi := min(n, lo+chunk)
		if lo >= hi {
			break
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			runSlice(lo, hi)
		}(lo, hi)
	}
	wg.Wait()
}

// batchMulCompressG2 computes compressed [scalars[i]]g2Gen into rawOut across all CPU cores
// using fixed-base zero-doubling multiplication and per-worker BatchJacobianToAffineG2.
func batchMulCompressG2(scalars []fr.Element, jacBuf []bn254.G2Jac, rawOut []byte, workers int) {
	initFixedG2Table()
	n := len(scalars)
	if n == 0 {
		return
	}
	runSlice := func(lo, hi int) {
		for i := lo; i < hi; i++ {
			jacBuf[i] = mulFixedG2Jac(&scalars[i])
		}
		aff := batchJacobianToAffineG2(jacBuf[lo:hi])
		for off := range aff {
			b := aff[off].Bytes()
			copy(rawOut[(lo+off)*bn254.SizeOfG2AffineCompressed:], b[:])
		}
	}
	if workers <= 1 || n < 128 {
		runSlice(0, n)
		return
	}
	w := min(workers, (n+63)/64)
	chunk := (n + w - 1) / w
	var wg sync.WaitGroup
	for wk := 0; wk < w; wk++ {
		lo := wk * chunk
		hi := min(n, lo+chunk)
		if lo >= hi {
			break
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			runSlice(lo, hi)
		}(lo, hi)
	}
	wg.Wait()
}

// g2SubgroupChecker verifies that every streamed on-curve G2 point lies in BN254 G2[r].
// For sectors smaller than g2SubgroupDirectMax, checks every point deterministically in parallel.
// For larger sectors, accumulates 7 independent 12-bit CSPRNG bucketed linear combinations
// across the entire sector and runs a single Pippenger triangle + IsInSubGroup() at Finalize()
// (soundness error <= 2^-84 since every prime factor of h2 = 2p - r exceeds 4096).
type g2SubgroupChecker struct {
	bucketed bool
	workers  int
	buckets  *[g2SubgroupTrials][g2SubgroupBuckets]bn254.G2Jac
	rBufs    [g2SubgroupTrials][]byte
}

func newG2SubgroupChecker(expectedCount, workers int) *g2SubgroupChecker {
	if expectedCount < g2SubgroupDirectMax {
		return &g2SubgroupChecker{bucketed: false, workers: workers}
	}
	c := &g2SubgroupChecker{
		bucketed: true,
		workers:  workers,
		buckets:  new([g2SubgroupTrials][g2SubgroupBuckets]bn254.G2Jac),
	}
	for tr := 0; tr < g2SubgroupTrials; tr++ {
		c.rBufs[tr] = make([]byte, streamG2Batch*2)
	}
	return c
}

func (c *g2SubgroupChecker) Reset() {
	if c.bucketed && c.buckets != nil {
		*c.buckets = [g2SubgroupTrials][g2SubgroupBuckets]bn254.G2Jac{}
	}
}

func (c *g2SubgroupChecker) Add(pts []bn254.G2Affine) bool {
	n := len(pts)
	if n == 0 {
		return true
	}
	if !c.bucketed {
		if c.workers <= 1 || n < 32 {
			for i := range pts {
				if !pts[i].IsInSubGroup() {
					return false
				}
			}
			return true
		}
		okFlags := make([]bool, c.workers)
		chunk := (n + c.workers - 1) / c.workers
		var wg sync.WaitGroup
		for wk := 0; wk < c.workers; wk++ {
			lo := wk * chunk
			hi := min(n, lo+chunk)
			if lo >= hi {
				okFlags[wk] = true
				continue
			}
			wg.Add(1)
			go func(wk, lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					if !pts[i].IsInSubGroup() {
						return
					}
				}
				okFlags[wk] = true
			}(wk, lo, hi)
		}
		wg.Wait()
		for _, ok := range okFlags {
			if !ok {
				return false
			}
		}
		return true
	}

	var trialOK [g2SubgroupTrials]bool
	var wg sync.WaitGroup
	wg.Add(g2SubgroupTrials)
	for tr := 0; tr < g2SubgroupTrials; tr++ {
		go func(tr int) {
			defer wg.Done()
			need := n * 2
			if len(c.rBufs[tr]) < need {
				c.rBufs[tr] = make([]byte, need)
			}
			rBytes := c.rBufs[tr][:need]
			if _, err := rand.Read(rBytes); err != nil {
				return
			}
			bkt := &c.buckets[tr]
			const mask = g2SubgroupBuckets - 1
			for i := 0; i < n; i++ {
				coeff := int(binary.LittleEndian.Uint16(rBytes[2*i:2*i+2])) & mask
				if coeff != 0 {
					bkt[coeff].AddMixed(&pts[i])
				}
			}
			trialOK[tr] = true
		}(tr)
	}
	wg.Wait()
	for _, ok := range trialOK {
		if !ok {
			return false
		}
	}
	return true
}

func (c *g2SubgroupChecker) Finalize() bool {
	if !c.bucketed {
		return true
	}
	var trialOK [g2SubgroupTrials]bool
	var wg sync.WaitGroup
	wg.Add(g2SubgroupTrials)
	for tr := 0; tr < g2SubgroupTrials; tr++ {
		go func(tr int) {
			defer wg.Done()
			bkt := &c.buckets[tr]
			var running, total bn254.G2Jac
			for k := g2SubgroupBuckets - 1; k >= 1; k-- {
				running.AddAssign(&bkt[k])
				total.AddAssign(&running)
			}
			trialOK[tr] = total.IsInSubGroup()
		}(tr)
	}
	wg.Wait()
	for _, ok := range trialOK {
		if !ok {
			return false
		}
	}
	return true
}

var seedDomainPrefix = []byte("praxis-demo/seed")

// fillRingElement writes ringElement(seed, i, j, len(out)) into out with zero heap allocations.
func fillRingElement(h hash.Hash, sumBuf *[sha512.Size]byte, seed []byte, i, j int, out []fr.Element) {
	var idx [12]byte
	binary.BigEndian.PutUint32(idx[0:], uint32(i))
	binary.BigEndian.PutUint32(idx[4:], uint32(j))
	for s := range out {
		binary.BigEndian.PutUint32(idx[8:], uint32(s))
		h.Reset()
		h.Write(seedDomainPrefix)
		h.Write(seed)
		h.Write(idx[:])
		out[s].SetBytes(h.Sum(sumBuf[:0]))
	}
}

// sampleRStream samples the centered Definition 5.3 integer vector using buffered crypto/rand
// rejection sampling (identical uniform distribution to sampleR with zero per-entry syscalls).
func sampleRStream(N int, g int64) ([]fr.Element, error) {
	r := make([]fr.Element, N+1)
	rng := bufio.NewReaderSize(rand.Reader, 64<<10)
	var u8 [8]byte
	var mask uint64
	if g > 1 {
		mask = (uint64(1) << bits.Len64(uint64(g-1))) - 1
	}
	nextVal := func() (int64, error) {
		if g <= 1 {
			return 2, nil
		}
		for {
			if _, err := io.ReadFull(rng, u8[:]); err != nil {
				return 0, err
			}
			v := binary.LittleEndian.Uint64(u8[:]) & mask
			if v < uint64(g) {
				return int64(v) + 2, nil
			}
		}
	}
	sum := new(big.Int)
	var tmp big.Int
	for i := 1; i <= N; i++ {
		v, err := nextVal()
		if err != nil {
			return nil, err
		}
		sum.Add(sum, tmp.SetInt64(v))
		r[i].SetInt64(v)
	}
	rStar, err := nextVal()
	if err != nil {
		return nil, err
	}
	a := new(big.Int).Mul(big.NewInt(int64(N)), big.NewInt(g+1))
	a.Add(a, big.NewInt(1))
	a.Rsh(a, 1)
	halfSum := sum.Rsh(sum, 1)
	r0 := a.Add(a, tmp.SetInt64(rStar))
	r0.Sub(r0, halfSum)
	r[0].SetBigInt(r0)
	return r, nil
}

// fillRandFr fills dst with uniform random Fr elements using buffered crypto/rand rejection sampling.
func fillRandFr(dst []fr.Element) error {
	rng := bufio.NewReaderSize(rand.Reader, 64<<10)
	var buf [32]byte
	for i := range dst {
		for {
			if _, err := io.ReadFull(rng, buf[:]); err != nil {
				return err
			}
			buf[0] &= 0x3f
			if err := dst[i].SetBytesCanonical(buf[:]); err == nil {
				break
			}
		}
	}
	return nil
}

// zAtTripleStream evaluates z[xMinus], z[xCirc], z[xPlus] directly from the
// seed oracle without materializing the n x (N+1) dense forms matrix phi
// (which would require ~57 GiB at Table 4 n=4608, N=391,693).
// Peak memory is 3*(N+1)*32 bytes (~36 MiB at N=391,693).
func (par Params) zAtTripleStream(seed []byte, N int, xMinus, xCirc, xPlus *fr.Element) (zMinus, zCirc, zPlus []fr.Element) {
	n, dr := par.NForms(), par.DR
	ell := (N + dr - 1) / dr

	powTable := func(x *fr.Element) []fr.Element {
		out := make([]fr.Element, n)
		out[0].SetOne()
		for e := 1; e < n; e++ {
			out[e].Mul(&out[e-1], x)
		}
		return out
	}
	pMinus := powTable(xMinus)
	pCirc := powTable(xCirc)
	pPlus := powTable(xPlus)

	zMinus = make([]fr.Element, N+1)
	zCirc = make([]fr.Element, N+1)
	zPlus = make([]fr.Element, N+1)
	// Row 0 contributes phi[0][0] = 1 with x^0 = 1.
	zMinus[0].SetOne()
	zCirc[0].SetOne()
	zPlus[0].SetOne()

	// Parallelize across packed column blocks j in 0..ell so each goroutine writes
	// to strictly disjoint indices of zMinus, zCirc, zPlus with zero synchronization.
	processRange := func(jLo, jHi int) {
		h := sha512.New()
		var sumBuf [sha512.Size]byte
		m := make([]fr.Element, dr)
		var tmp fr.Element
		for j := jLo; j < jHi; j++ {
			if j == 0 {
				for i := 1; i <= par.K; i++ {
					fillRingElement(h, &sumBuf, seed, i, 0, m)
					base := i * dr
					for s := 0; s < dr; s++ {
						tmp.Mul(&m[s], &pMinus[base+s])
						zMinus[0].Add(&zMinus[0], &tmp)
						tmp.Mul(&m[s], &pCirc[base+s])
						zCirc[0].Add(&zCirc[0], &tmp)
						tmp.Mul(&m[s], &pPlus[base+s])
						zPlus[0].Add(&zPlus[0], &tmp)
					}
				}
				continue
			}
			uStart := (j-1)*dr + 1
			uEnd := min(N, uStart+dr-1)
			tCount := uEnd - uStart + 1
			for i := 1; i <= par.K; i++ {
				fillRingElement(h, &sumBuf, seed, i, j, m)
				base := i * dr
				for t := 0; t < tCount; t++ {
					u := uStart + t
					var accM, accC, accP fr.Element
					for s := 0; s < dr; s++ {
						var coef fr.Element
						if s >= t {
							coef = m[s-t]
						} else {
							coef.Neg(&m[dr+s-t])
						}
						tmp.Mul(&coef, &pMinus[base+s])
						accM.Add(&accM, &tmp)
						tmp.Mul(&coef, &pCirc[base+s])
						accC.Add(&accC, &tmp)
						tmp.Mul(&coef, &pPlus[base+s])
						accP.Add(&accP, &tmp)
					}
					zMinus[u].Add(&zMinus[u], &accM)
					zCirc[u].Add(&zCirc[u], &accC)
					zPlus[u].Add(&zPlus[u], &accP)
				}
			}
		}
	}

	totalBlocks := ell + 1
	workers := min(runtime.NumCPU(), totalBlocks)
	if workers <= 1 || par.K*totalBlocks < 16 {
		processRange(0, totalBlocks)
		return zMinus, zCirc, zPlus
	}
	chunk := (totalBlocks + workers - 1) / workers
	var wg sync.WaitGroup
	for wk := 0; wk < workers; wk++ {
		lo := wk * chunk
		hi := min(totalBlocks, lo+chunk)
		if lo >= hi {
			break
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			processRange(lo, hi)
		}(lo, hi)
	}
	wg.Wait()
	return zMinus, zCirc, zPlus
}

// weightsOfStream computes decryption's quadratic weights U(w), V(w) directly
// from the seed oracle without materializing phi[n][N+1] (only O(n) RAM = 147 KiB at Table 4).
func (par Params) weightsOfStream(f field, seed []byte, N int, w []bool) weights {
	n, dr := f.n, par.DR
	ell := (N + dr - 1) / dr
	z := make(poly.Poly, n)
	if w[0] {
		z[0].SetOne()
	}

	// Precompute active bit offsets in each packed block j >= 1 so empty blocks skip hashing entirely.
	activeBlocks := make([]int, 0, ell)
	activeTs := make([][]int, ell+1)
	for j := 1; j <= ell; j++ {
		uStart := (j-1)*dr + 1
		uEnd := min(N, uStart+dr-1)
		var ts []int
		for t := 0; t <= uEnd-uStart; t++ {
			if w[uStart+t] {
				ts = append(ts, t)
			}
		}
		if len(ts) > 0 {
			activeBlocks = append(activeBlocks, j)
			activeTs[j] = ts
		}
	}

	workers := max(1, runtime.NumCPU())
	fillRow := func(i int) {
		base := i * dr
		if w[0] {
			h0 := sha512.New()
			var sum0 [sha512.Size]byte
			m0 := make([]fr.Element, dr)
			fillRingElement(h0, &sum0, seed, i, 0, m0)
			for s := 0; s < dr; s++ {
				z[base+s].Add(&z[base+s], &m0[s])
			}
		}
		if par.K < workers && len(activeBlocks) >= 1024 && workers > 1 {
			// Parallelize across activeBlocks when K is small (e.g. Groth16 K=1, N=2.41M).
			chunk := (len(activeBlocks) + workers - 1) / workers
			locals := make([][]fr.Element, workers)
			var wg sync.WaitGroup
			for wk := 0; wk < workers; wk++ {
				lo := wk * chunk
				hi := min(len(activeBlocks), lo+chunk)
				if lo >= hi {
					continue
				}
				locals[wk] = make([]fr.Element, dr)
				wg.Add(1)
				go func(wk, lo, hi int) {
					defer wg.Done()
					h := sha512.New()
					var sumBuf [sha512.Size]byte
					m := make([]fr.Element, dr)
					loc := locals[wk]
					for idx := lo; idx < hi; idx++ {
						j := activeBlocks[idx]
						fillRingElement(h, &sumBuf, seed, i, j, m)
						for _, t := range activeTs[j] {
							for s := 0; s < dr; s++ {
								if s >= t {
									loc[s].Add(&loc[s], &m[s-t])
								} else {
									loc[s].Sub(&loc[s], &m[dr+s-t])
								}
							}
						}
					}
				}(wk, lo, hi)
			}
			wg.Wait()
			for wk := 0; wk < workers; wk++ {
				if locals[wk] != nil {
					for s := 0; s < dr; s++ {
						z[base+s].Add(&z[base+s], &locals[wk][s])
					}
				}
			}
			return
		}
		h := sha512.New()
		var sumBuf [sha512.Size]byte
		m := make([]fr.Element, dr)
		for _, j := range activeBlocks {
			fillRingElement(h, &sumBuf, seed, i, j, m)
			for _, t := range activeTs[j] {
				for s := 0; s < dr; s++ {
					if s >= t {
						z[base+s].Add(&z[base+s], &m[s-t])
					} else {
						z[base+s].Sub(&z[base+s], &m[dr+s-t])
					}
				}
			}
		}
	}

	if par.K < 8 {
		for i := 1; i <= par.K; i++ {
			fillRow(i)
		}
	} else {
		rowWorkers := min(workers, par.K)
		var wg sync.WaitGroup
		rowCh := make(chan int, par.K)
		for i := 1; i <= par.K; i++ {
			rowCh <- i
		}
		close(rowCh)
		for wk := 0; wk < rowWorkers; wk++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range rowCh {
					fillRow(i)
				}
			}()
		}
		wg.Wait()
	}

	var minus, cMinus, cPlus fr.Element
	minus.SetInt64(-1)
	cMinus.Inverse(&f.omega)
	cMinus.Neg(&cMinus)
	cPlus.Neg(&f.omega)
	wt := weights{
		zMinus: z.Substitute(&cMinus),
		zCirc:  z.Substitute(&minus),
		zPlus:  z.Substitute(&cPlus),
	}
	mul := poly.Mul
	if par.Fast {
		mul = poly.MulFFT
	}
	wt.U = f.reduce(mul(z, wt.zMinus))
	wt.V = f.reduce(mul(z, wt.zCirc))
	return wt
}

// EncStreamTo encrypts msg directly into dst using the exact "praxis-demo ciphertext 1\n"
// compressed wire format while keeping RAM O(N + n) instead of O(n*N + lenG1 + lenG2).
// Ciphertexts written by EncStreamTo are byte-for-byte decodable by both DecStreamFrom
// and (when small enough to fit in RAM) ReadCiphertext + Dec.
func EncStreamTo(pp *Public, msg []byte, dst io.Writer) (EncReport, error) {
	if pp == nil {
		return EncReport{}, fmt.Errorf("nil public parameters")
	}
	start := time.Now()
	par, N, f := pp.Par, pp.S.N, pp.fld
	n := par.NForms()
	l := pp.layout()
	workers := max(1, runtime.NumCPU())

	if l.lenG1() > maxFieldLen || l.lenG2() > maxFieldLen {
		return EncReport{}, fmt.Errorf("ciphertext element count exceeds wire format limit %d", maxFieldLen)
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return EncReport{}, err
	}

	// Sample Figure 9 coins (identical distribution to EncDetailed, buffered CSPRNG).
	r, err := sampleRStream(N, par.G)
	if err != nil {
		return EncReport{}, err
	}
	y := make([]fr.Element, N+1)
	if err := fillRandFr(y); err != nil {
		return EncReport{}, err
	}
	var tau, zpTau, omega12 fr.Element
	for {
		if _, err := tau.SetRandom(); err != nil {
			return EncReport{}, err
		}
		if zpTau = pp.ZP.Eval(&tau); !zpTau.IsZero() {
			break
		}
	}
	if _, err := omega12.SetRandom(); err != nil {
		return EncReport{}, err
	}
	omega22, alpha, pi := randNonzero(), randNonzero(), randNonzero()
	sKind := [3]fr.Element{randNonzero(), randNonzero(), randNonzero()}
	ups := randNonzero()
	zeta, zeta1, zeta2 := randNonzero(), randNonzero(), randNonzero()
	eta := [3]fr.Element{randNonzero(), randNonzero(), randNonzero()}

	omega2 := pow(&f.omega, 2)
	var eps, one fr.Element
	one.SetOne()
	onePlus := make([]fr.Element, par.K1)
pick:
	for {
		eps = randNonzero()
		var w2 fr.Element
		w2.SetOne()
		for k1 := 0; k1 < par.K1; k1++ {
			onePlus[k1].Mul(&eps, &w2)
			onePlus[k1].Add(&onePlus[k1], &one)
			if onePlus[k1].IsZero() {
				continue pick
			}
			w2.Mul(&w2, &omega2)
		}
		break
	}

	// Line 5: leg scalars.
	piK := make([]fr.Element, par.K1)
	for k1 := range piK {
		piK[k1] = pow(&ups, 2*k1)
		piK[k1].Mul(&piK[k1], &pi)
		piK[k1].Mul(&piK[k1], &onePlus[k1])
	}
	sLeg := make([]fr.Element, par.legs())
	for leg := range sLeg {
		sLeg[leg] = pow(&ups, par.legExp(leg))
		sLeg[leg].Mul(&sLeg[leg], &sKind[par.legKind(leg)])
	}

	// A_i(tau), B_i(tau) via Lagrange weights.
	lag := make([]fr.Element, pp.D)
	for i := range lag {
		lag[i].Sub(&tau, &pp.Points[i])
	}
	lag = fr.BatchInvert(lag)
	aTau := make([]fr.Element, N+1)
	bTau := make([]fr.Element, N+1)
	var tmp fr.Element
	for i := range lag {
		lag[i].Mul(&lag[i], &pp.Weights[i])
		lag[i].Mul(&lag[i], &zpTau)
		for _, term := range pp.A[i] {
			tmp.Mul(&term.V, &lag[i])
			aTau[term.I].Add(&aTau[term.I], &tmp)
		}
		for _, term := range pp.B[i] {
			tmp.Mul(&term.V, &lag[i])
			bTau[term.I].Add(&bTau[term.I], &tmp)
		}
	}
	lrhoTau := lag[pp.rhoIndex()]
	zTau, z0Tau := pp.Z.Eval(&tau), pp.Z0.Eval(&tau)

	var kappa, ak fr.Element
	kappa.Mul(&piK[0], &sLeg[0])
	kappa.Mul(&kappa, &lrhoTau)
	ak.Mul(&alpha, &kappa)

	// Streamed tie vectors zMinus, zCirc, zPlus (3*(N+1) scalars, ZERO phi matrix!).
	var xMinus, xCirc, xPlus fr.Element
	xCirc.Neg(&ups)
	xPlus.Mul(&xCirc, &f.omega)
	xMinus.Div(&xCirc, &f.omega)
	zMinus, zCirc, zPlus := par.zAtTripleStream(seed, N, &xMinus, &xCirc, &xPlus)

	_, _, g1Gen, g2Gen := bn254.Generators()
	gt, err := bn254.Pair([]bn254.G1Affine{g1Gen}, []bn254.G2Affine{g2Gen})
	if err != nil {
		return EncReport{}, err
	}
	var key, ka bn254.GT
	key.Exp(gt, kappa.BigInt(new(big.Int)))
	ka.Exp(gt, ak.BigInt(new(big.Int)))
	encMsg := xor(msg, keyPadFor(&key, len(msg), par.SignClassKDF))

	cw := &countingWriter{w: dst}
	bw := bufio.NewWriterSize(cw, streamBufBytes)
	writeU32 := func(v int) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v))
		_, _ = bw.Write(b[:])
	}

	// Header (matches Ciphertext.WriteTo byte-for-byte).
	_, _ = bw.Write([]byte(magic))
	writeU32(len(seed))
	_, _ = bw.Write(seed)
	writeU32(len(encMsg))
	_, _ = bw.Write(encMsg)
	kaBytes := ka.Bytes()
	_, _ = bw.Write(kaBytes[:])

	// Stream G1 elements in fixed-size chunks using parallel zero-doubling fixed-base G1 engine.
	writeU32(l.lenG1())
	g1Buf := make([]fr.Element, 0, streamG1Batch)
	g1JacBuf := make([]bn254.G1Jac, streamG1Batch)
	g1RawBuf := make([]byte, streamG1Batch*bn254.SizeOfG1AffineCompressed)
	flushG1 := func() error {
		cnt := len(g1Buf)
		if cnt == 0 {
			return nil
		}
		batchMulCompressG1(g1Buf, g1JacBuf, g1RawBuf, workers)
		if _, err := bw.Write(g1RawBuf[:cnt*bn254.SizeOfG1AffineCompressed]); err != nil {
			return err
		}
		g1Buf = g1Buf[:0]
		return nil
	}
	emitG1 := func(s fr.Element) error {
		g1Buf = append(g1Buf, s)
		if len(g1Buf) == cap(g1Buf) {
			return flushG1()
		}
		return nil
	}

	// G1 layout order: f(k1, i, 0..1), y(i), pquo(k), prem(k).
	for k1 := 0; k1 < par.K1; k1++ {
		for i := 0; i <= N; i++ {
			var s0, s1, u fr.Element
			s0.Mul(&piK[k1], &y[i])
			tmp.Mul(&aTau[i], &omega22)
			u.Mul(&y[i], &omega12)
			u.Add(&u, &tmp)
			s1.Mul(&piK[k1], &u)
			if err := emitG1(s0); err != nil {
				return EncReport{}, err
			}
			if err := emitG1(s1); err != nil {
				return EncReport{}, err
			}
		}
	}
	for i := 0; i <= N; i++ {
		var s fr.Element
		s.Mul(&zeta2, &y[i])
		if err := emitG1(s); err != nil {
			return EncReport{}, err
		}
	}
	var tp fr.Element
	tp.SetOne()
	for k := 0; k < pp.Delta; k++ {
		var s fr.Element
		s.Mul(&zeta, &tp)
		if err := emitG1(s); err != nil {
			return EncReport{}, err
		}
		tp.Mul(&tp, &tau)
	}
	tp.SetOne()
	for k := 0; k < pp.DeltaPrime; k++ {
		if k%pp.Nu != 0 {
			var s fr.Element
			s.Mul(&zeta1, &tp)
			if err := emitG1(s); err != nil {
				return EncReport{}, err
			}
		}
		tp.Mul(&tp, &tau)
	}
	if err := flushG1(); err != nil {
		return EncReport{}, err
	}
	// Release G1 scratch buffers before allocating G2 scratch buffers to minimize peak HeapAlloc.
	g1Buf, g1JacBuf, g1RawBuf = nil, nil, nil

	// Precompute scalar constants shared across G2 (plain) and G2a (alpha) streaming passes.
	var epsInv, o22Inv, o12Over22, zetaInv, zeta1Inv, zeta2Inv, zKey fr.Element
	epsInv.Inverse(&eps)
	o22Inv.Inverse(&omega22)
	o12Over22.Mul(&omega12, &o22Inv)
	zetaInv.Inverse(&zeta)
	zeta1Inv.Inverse(&zeta1)
	zeta2Inv.Inverse(&zeta2)
	zKey.Sub(&tau, &pp.Points[pp.rhoIndex()])
	zKey.Mul(&zKey, &zTau)
	tauDelta := pow(&tau, pp.Delta)
	tauDeltaP := pow(&tau, pp.DeltaPrime)
	pUps := pow(&ups, n)
	pUps.Sub(&pUps, &f.c0)
	var tieBase fr.Element
	tieBase.Mul(&pi, &zeta2Inv)

	// Precompute bquo and brem cell scalars (only 3n/2*(J+J') elements = ~4.8 MiB at Table 4).
	cells := par.Cells()
	bquoSc := make([]fr.Element, l.jQuo*cells)
	bremSc := make([]fr.Element, l.jRem*cells)
	for k1 := 0; k1 < par.K1; k1++ {
		for leg := 0; leg < par.legs(); leg++ {
			cel := par.cell(k1, leg)
			var gamma fr.Element
			gamma.Mul(&piK[k1], &sLeg[leg])
			zc := zTau
			if cel == 0 {
				zc = zKey
			}
			var curQuo fr.Element
			curQuo.Mul(&gamma, &zc)
			curQuo.Mul(&curQuo, &zetaInv)
			for j := 0; j < l.jQuo; j++ {
				bquoSc[j*cells+cel] = curQuo
				curQuo.Mul(&curQuo, &tauDelta)
			}
			var curRem fr.Element
			curRem.Mul(&gamma, &z0Tau)
			curRem.Mul(&curRem, &zeta1Inv)
			for j := 0; j < l.jRem; j++ {
				bremSc[j*cells+cel] = curRem
				curRem.Mul(&curRem, &tauDeltaP)
			}
		}
	}

	writeU32(l.lenG2())
	g2Buf := make([]fr.Element, 0, streamG2Batch)
	g2JacBuf := make([]bn254.G2Jac, streamG2Batch)
	g2RawBuf := make([]byte, streamG2Batch*bn254.SizeOfG2AffineCompressed)
	flushG2 := func() error {
		cnt := len(g2Buf)
		if cnt == 0 {
			return nil
		}
		batchMulCompressG2(g2Buf, g2JacBuf, g2RawBuf, workers)
		if _, err := bw.Write(g2RawBuf[:cnt*bn254.SizeOfG2AffineCompressed]); err != nil {
			return err
		}
		g2Buf = g2Buf[:0]
		return nil
	}

	// Stream G2 (scale = 1) then G2a (scale = alpha) using identical O(1)-memory generators.
	var oneScale fr.Element
	oneScale.SetOne()
	crossOf := [crossFamilies]struct {
		a   int
		eps *fr.Element
	}{{0, &eps}, {1, &eps}, {1, &epsInv}, {2, &eps}, {2, &epsInv}}

	for _, sectorScale := range []*fr.Element{&oneScale, &alpha} {
		emitG2 := func(s fr.Element) error {
			if sectorScale != &oneScale {
				s.Mul(&s, sectorScale)
			}
			g2Buf = append(g2Buf, s)
			if len(g2Buf) == cap(g2Buf) {
				return flushG2()
			}
			return nil
		}

		// 1. h(leg, j, 0..1)
		for leg := 0; leg < par.legs(); leg++ {
			kl := par.legExp(leg)
			p1 := pow(&ups, kl)
			p2 := pow(&xPlus, kl)
			p2.Mul(&p2, &epsInv)
			isV := par.legKind(leg) == kindV
			for j := 0; j <= N; j++ {
				var maskVal, a, b fr.Element
				if isV {
					a.Mul(&eta[2], &zPlus[j])
					b.Mul(&eta[0], &zMinus[j])
					a.Sub(&a, &b)
					maskVal.Mul(&p1, &a)
				} else {
					a.Mul(&eta[0], &zCirc[j])
					b.Mul(&eta[1], &zPlus[j])
					a.Add(&a, &b)
					a.Mul(&a, &p1)
					b.Mul(&eta[1], &zMinus[j])
					tmp.Mul(&eta[2], &zCirc[j])
					b.Add(&b, &tmp)
					b.Mul(&b, &p2)
					maskVal.Sub(&a, &b)
				}
				var h1, h2, s0, s1 fr.Element
				h1.Add(&r[j], &aTau[j])
				h1.Mul(&h1, &sLeg[leg])
				h1.Add(&h1, &maskVal)
				h2.Sub(&bTau[j], &y[j])
				h2.Mul(&h2, &sLeg[leg])
				tmp.Mul(&h2, &o12Over22)
				s0.Sub(&h1, &tmp)
				s1.Mul(&h2, &o22Inv)
				if err := emitG2(s0); err != nil {
					return EncReport{}, err
				}
				if err := emitG2(s1); err != nil {
					return EncReport{}, err
				}
			}
		}
		// 2. s(leg)
		for leg := 0; leg < par.legs(); leg++ {
			if err := emitG2(sLeg[leg]); err != nil {
				return EncReport{}, err
			}
		}
		// 3. bquo(cell, j)
		for i := range bquoSc {
			if err := emitG2(bquoSc[i]); err != nil {
				return EncReport{}, err
			}
		}
		// 4. brem(cell, j)
		for i := range bremSc {
			if err := emitG2(bremSc[i]); err != nil {
				return EncReport{}, err
			}
		}
		// 5. tie(a, e) for a in 0..2, e in 0..n-2
		for aIdx := 0; aIdx < 3; aIdx++ {
			var cur fr.Element
			cur.Mul(&tieBase, &eta[aIdx])
			cur.Mul(&cur, &pUps)
			for e := 0; e <= n-2; e++ {
				if err := emitG2(cur); err != nil {
					return EncReport{}, err
				}
				cur.Mul(&cur, &ups)
			}
		}
		// 6. cross(fam, e) for fam in 0..4, e in 0..2n-2
		for _, cf := range crossOf {
			var cur fr.Element
			cur.Mul(&tieBase, &eta[cf.a])
			cur.Mul(&cur, cf.eps)
			for e := 0; e <= 2*n-2; e++ {
				if err := emitG2(cur); err != nil {
					return EncReport{}, err
				}
				cur.Mul(&cur, &ups)
			}
		}
		if err := flushG2(); err != nil {
			return EncReport{}, err
		}
	}

	if err := bw.Flush(); err != nil {
		return EncReport{}, err
	}
	if cw.err != nil {
		return EncReport{}, cw.err
	}

	g1Count, g2Count := pp.Counts()
	return EncReport{
		EncDur: time.Since(start),
		G1:     g1Count,
		G2:     g2Count,
		Bytes:  int(cw.n),
		J:      l.jQuo,
		Delta:  pp.Delta,
		JPrime: l.jRem,
		DeltaP: pp.DeltaPrime,
		Forms:  n,
		Cells:  cells,
	}, nil
}

// DecStreamFrom decrypts a compressed Praxis ciphertext straight from src in a single
// sequential pass without materializing the ciphertext point slices or phi matrix in RAM.
// When unchecked is false, verifies pp.S.IsWitness(w) first (matching DecDetailed).
func DecStreamFrom(pp *Public, src io.Reader, w []bool, unchecked bool) ([]byte, DecReport, error) {
	var rep DecReport
	totalStart := time.Now()
	if pp == nil || len(w) != pp.S.N+1 || !w[0] {
		return nil, rep, ErrNotWitness
	}
	if !unchecked && !pp.S.IsWitness(w) {
		return nil, rep, ErrNotWitness
	}

	br := bufio.NewReaderSize(src, streamBufBytes)
	readExact := func(dst []byte) error {
		_, err := io.ReadFull(br, dst)
		return err
	}
	readU32 := func() (int, error) {
		var b [4]byte
		if err := readExact(b[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint32(b[:])
		if v > maxFieldLen {
			return 0, fmt.Errorf("length %d too large", v)
		}
		return int(v), nil
	}
	readBytes := func() ([]byte, error) {
		n, err := readU32()
		if err != nil {
			return nil, err
		}
		out := make([]byte, n)
		if err := readExact(out); err != nil {
			return nil, err
		}
		return out, nil
	}

	head := make([]byte, len(magic))
	if err := readExact(head); err != nil || string(head) != magic {
		return nil, rep, fmt.Errorf("not a praxis-demo ciphertext")
	}
	seed, err := readBytes()
	if err != nil {
		return nil, rep, err
	}
	encMsg, err := readBytes()
	if err != nil {
		return nil, rep, err
	}
	kaRaw := make([]byte, bn254.SizeOfGT)
	if err := readExact(kaRaw); err != nil {
		return nil, rep, err
	}
	var ka bn254.GT
	if err := ka.SetBytes(kaRaw); err != nil {
		return nil, rep, err
	}
	if !inGT(&ka) {
		return nil, rep, fmt.Errorf("invalid GT element: subgroup check failed")
	}

	par, N, f := pp.Par, pp.S.N, pp.fld
	n := par.NForms()
	l := pp.layout()
	rep.Pairings = 18*par.K2 + 4*l.jQuo + 2*l.jRem + 2

	n1, err := readU32()
	if err != nil {
		return nil, rep, err
	}
	if n1 != l.lenG1() {
		return nil, rep, fmt.Errorf("ciphertext G1 count %d does not match layout %d", n1, l.lenG1())
	}

	// Lines 1-2: streamed weights (ZERO phi matrix!).
	t0 := time.Now()
	wt := par.weightsOfStream(f, seed, N, w)
	xiKey := par.xi(&wt, 0, 0)
	if xiKey.IsZero() {
		rep.TotalDur = time.Since(totalStart)
		return nil, rep, ErrFailed
	}
	cells := par.Cells()
	xi := make([]fr.Element, cells)
	for k1 := 0; k1 < par.K1; k1++ {
		for leg := 0; leg < par.legs(); leg++ {
			xi[par.cell(k1, leg)] = par.xi(&wt, k1, leg)
		}
	}
	rep.FormsDur = time.Since(t0)

	// Lines 3-4: QAP quotients and tie/cross cancellation polynomials.
	tQAP := time.Now()
	hKey, hOth, rem, exact := pp.quotients(w)
	rep.ExactQAP = exact

	var negOmega fr.Element
	negOmega.Neg(&f.omega)
	u1, v1, u2 := make(poly.Poly, n), make(poly.Poly, n), make(poly.Poly, n)
	for k := 0; k < n; k++ {
		k1 := (k / 2) % par.K1
		a := pow(&f.omega, 2*k1)
		b := pow(&negOmega, k-2*k1)
		u1[k].Mul(&wt.U[k], &a)
		v1[k].Mul(&wt.V[k], &a)
		u2[k].Mul(&wt.U[k], &b)
	}
	uRot := wt.U.Substitute(&negOmega)
	modulus := f.modulus()
	mulPoly := poly.Mul
	divPoly := poly.DivMod
	if par.Fast {
		mulPoly = poly.MulFFT
		divPoly = poly.DivModFFT
	}
	tieQuot := func(a, b poly.Poly) poly.Poly {
		q, _ := divPoly(poly.Sub(a, b), modulus)
		return q
	}
	negPoly := func(p poly.Poly) poly.Poly { return poly.Sub(nil, p) }
	x0 := [3]poly.Poly{
		tieQuot(mulPoly(wt.U, wt.zCirc), mulPoly(wt.V, wt.zMinus)),
		tieQuot(mulPoly(wt.U, wt.zPlus), mulPoly(uRot, wt.zMinus)),
		tieQuot(mulPoly(wt.V, wt.zPlus), mulPoly(uRot, wt.zCirc)),
	}
	var xc [crossFamilies]poly.Poly
	xc[cross1Plus] = poly.Sub(mulPoly(u1, wt.zCirc), mulPoly(v1, wt.zMinus))
	xc[cross2Plus] = mulPoly(u1, wt.zPlus)
	xc[cross2Minus] = negPoly(mulPoly(u2, wt.zMinus))
	xc[cross3Plus] = mulPoly(v1, wt.zPlus)
	xc[cross3Minus] = negPoly(mulPoly(u2, wt.zCirc))
	rep.QAPDur = time.Since(tQAP)

	// Helper: parallel batch decode of compressed G1 points (verifies every point on curve).
	workers := max(1, runtime.NumCPU())
	decodeG1Chunk := func(raw []byte, count int, dst []bn254.G1Affine) error {
		if count < 256 || workers == 1 {
			for i := 0; i < count; i++ {
				if _, err := dst[i].SetBytes(raw[i*bn254.SizeOfG1AffineCompressed : (i+1)*bn254.SizeOfG1AffineCompressed]); err != nil {
					return err
				}
			}
			return nil
		}
		var wg sync.WaitGroup
		errs := make([]error, workers)
		chunk := (count + workers - 1) / workers
		for wk := 0; wk < workers; wk++ {
			lo := wk * chunk
			hi := min(count, lo+chunk)
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func(wk, lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					if _, err := dst[i].SetBytes(raw[i*bn254.SizeOfG1AffineCompressed : (i+1)*bn254.SizeOfG1AffineCompressed]); err != nil {
						errs[wk] = err
						return
					}
				}
			}(wk, lo, hi)
		}
		wg.Wait()
		for _, e := range errs {
			if e != nil {
				return e
			}
		}
		return nil
	}

	// Helper: parallel batch decode of compressed G2 points (verifies canonical encoding & twist curve
	// on every point; G2[r] prime-order subgroup membership is verified across the full sector via g2SubgroupChecker).
	decodeG2Chunk := func(raw []byte, count int, dst []bn254.G2Affine) error {
		if count < 128 || workers == 1 {
			dec := bn254.NewDecoder(bytes.NewReader(raw[:count*bn254.SizeOfG2AffineCompressed]), bn254.NoSubgroupChecks())
			for i := 0; i < count; i++ {
				if err := dec.Decode(&dst[i]); err != nil {
					return err
				}
			}
			return nil
		}
		var wg sync.WaitGroup
		errs := make([]error, workers)
		chunk := (count + workers - 1) / workers
		for wk := 0; wk < workers; wk++ {
			lo := wk * chunk
			hi := min(count, lo+chunk)
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func(wk, lo, hi int) {
				defer wg.Done()
				sub := raw[lo*bn254.SizeOfG2AffineCompressed : hi*bn254.SizeOfG2AffineCompressed]
				dec := bn254.NewDecoder(bytes.NewReader(sub), bn254.NoSubgroupChecks())
				for i := lo; i < hi; i++ {
					if err := dec.Decode(&dst[i]); err != nil {
						errs[wk] = err
						return
					}
				}
			}(wk, lo, hi)
		}
		wg.Wait()
		for _, e := range errs {
			if e != nil {
				return e
			}
		}
		return nil
	}

	// Stream G1 section in chunks: accumulate fw[k1], yw, pquo, prem!
	tPair := time.Now()
	fw := make([][2]bn254.G1Jac, par.K1)
	var yw bn254.G1Jac
	rawG1 := make([]byte, streamG1Batch*bn254.SizeOfG1AffineCompressed)
	ptsG1 := make([]bn254.G1Affine, streamG1Batch)

	readG1Count := func(total int, onBatch func(baseIdx int, pts []bn254.G1Affine)) error {
		done := 0
		for done < total {
			cnt := min(streamG1Batch, total-done)
			buf := rawG1[:cnt*bn254.SizeOfG1AffineCompressed]
			if err := readExact(buf); err != nil {
				return err
			}
			if err := decodeG1Chunk(buf, cnt, ptsG1[:cnt]); err != nil {
				return err
			}
			onBatch(done, ptsG1[:cnt])
			done += cnt
		}
		return nil
	}

	// 1a. f(k1, i, 0..1) — parallelize G1 witness accumulation across workers when batch is large.
	n1Count := N + 1
	localFw := make([][][2]bn254.G1Jac, workers)
	for wk := range localFw {
		localFw[wk] = make([][2]bn254.G1Jac, par.K1)
	}
	if err := readG1Count(2*par.K1*n1Count, func(baseIdx int, pts []bn254.G1Affine) {
		cnt := len(pts)
		if workers <= 1 || cnt < 1024 {
			for off, pt := range pts {
				idx := baseIdx + off
				coord := idx & 1
				pairIdx := idx >> 1
				k1 := pairIdx / n1Count
				i := pairIdx % n1Count
				if w[i] {
					fw[k1][coord].AddMixed(&pt)
				}
			}
			return
		}
		chunk := (cnt + workers - 1) / workers
		var wg sync.WaitGroup
		for wk := 0; wk < workers; wk++ {
			lo := wk * chunk
			hi := min(cnt, lo+chunk)
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func(wk, lo, hi int) {
				defer wg.Done()
				loc := localFw[wk]
				for off := lo; off < hi; off++ {
					idx := baseIdx + off
					coord := idx & 1
					pairIdx := idx >> 1
					k1 := pairIdx / n1Count
					i := pairIdx % n1Count
					if w[i] {
						loc[k1][coord].AddMixed(&pts[off])
					}
				}
			}(wk, lo, hi)
		}
		wg.Wait()
	}); err != nil {
		return nil, rep, err
	}
	for wk := range localFw {
		for k1 := 0; k1 < par.K1; k1++ {
			fw[k1][0].AddAssign(&localFw[wk][k1][0])
			fw[k1][1].AddAssign(&localFw[wk][k1][1])
		}
	}
	localFw = nil

	// 1b. y(i) — parallelize G1 witness accumulation across workers when batch is large.
	localYw := make([]bn254.G1Jac, workers)
	if err := readG1Count(n1Count, func(baseIdx int, pts []bn254.G1Affine) {
		cnt := len(pts)
		if workers <= 1 || cnt < 1024 {
			for off, pt := range pts {
				if w[baseIdx+off] {
					yw.AddMixed(&pt)
				}
			}
			return
		}
		chunk := (cnt + workers - 1) / workers
		var wg sync.WaitGroup
		for wk := 0; wk < workers; wk++ {
			lo := wk * chunk
			hi := min(cnt, lo+chunk)
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func(wk, lo, hi int) {
				defer wg.Done()
				var acc bn254.G1Jac
				for off := lo; off < hi; off++ {
					if w[baseIdx+off] {
						acc.AddMixed(&pts[off])
					}
				}
				localYw[wk].AddAssign(&acc)
			}(wk, lo, hi)
		}
		wg.Wait()
	}); err != nil {
		return nil, rep, err
	}
	for wk := range localYw {
		yw.AddAssign(&localYw[wk])
	}

	// 1c. pquo(k) -> accumulate pKey[j], pOth[j] chunked MSMs on the fly
	pKeyJac := make([]bn254.G1Jac, l.jQuo)
	pOthJac := make([]bn254.G1Jac, l.jQuo)
	if err := readG1Count(pp.Delta, func(baseIdx int, pts []bn254.G1Affine) {
		cnt := len(pts)
		for j := 0; j < l.jQuo; j++ {
			subKey := msm1(pts, chunkCoeffs(hKey, j*pp.Delta+baseIdx, cnt))
			subOth := msm1(pts, chunkCoeffs(hOth, j*pp.Delta+baseIdx, cnt))
			pKeyJac[j].AddMixed(&subKey)
			pOthJac[j].AddMixed(&subOth)
		}
	}); err != nil {
		return nil, rep, err
	}
	pKey := bn254.BatchJacobianToAffineG1(pKeyJac)
	pOth := bn254.BatchJacobianToAffineG1(pOthJac)

	// 1d. prem(k) -> build k-index map for non-multiples of nu and stream pRem[j]
	remExps := make([]int, 0, l.nRem)
	for k := 0; k < pp.DeltaPrime; k++ {
		if k%pp.Nu != 0 {
			remExps = append(remExps, k)
		}
	}
	pRemJac := make([]bn254.G1Jac, l.jRem)
	if err := readG1Count(l.nRem, func(baseIdx int, pts []bn254.G1Affine) {
		sc := make([]fr.Element, len(pts))
		for j := 0; j < l.jRem; j++ {
			baseExp := j * pp.DeltaPrime
			for off := range pts {
				sc[off] = rem.Coeff(baseExp + remExps[baseIdx+off])
			}
			subRem := msm1(pts, sc)
			pRemJac[j].AddMixed(&subRem)
		}
	}); err != nil {
		return nil, rep, err
	}
	pRem := bn254.BatchJacobianToAffineG1(pRemJac)
	// Release G1 decode scratch before allocating G2 decode scratch.
	rawG1, ptsG1 = nil, nil

	// Convert accumulated G1 points to affine & combine across columns (parallelized across legs).
	fw0Jac := make([]bn254.G1Jac, par.K1)
	fw1Jac := make([]bn254.G1Jac, par.K1)
	for k1 := range fw {
		fw0Jac[k1] = fw[k1][0]
		fw1Jac[k1] = fw[k1][1]
	}
	fwAff := [2][]bn254.G1Affine{
		bn254.BatchJacobianToAffineG1(fw0Jac),
		bn254.BatchJacobianToAffineG1(fw1Jac),
	}
	fLeg := make([][2]bn254.G1Affine, par.legs())
	if par.legs() >= 4 && workers > 1 {
		var wg sync.WaitGroup
		legCh := make(chan int, par.legs())
		for leg := range fLeg {
			legCh <- leg
		}
		close(legCh)
		wLeg := min(workers, par.legs())
		wg.Add(wLeg)
		for wk := 0; wk < wLeg; wk++ {
			go func() {
				defer wg.Done()
				col := make([]fr.Element, par.K1)
				for leg := range legCh {
					for k1 := range col {
						col[k1] = xi[par.cell(k1, leg)]
					}
					fLeg[leg][0] = msm1(fwAff[0], col)
					fLeg[leg][1] = msm1(fwAff[1], col)
				}
			}()
		}
		wg.Wait()
	} else {
		col := make([]fr.Element, par.K1)
		for leg := range fLeg {
			for k1 := range col {
				col[k1] = xi[par.cell(k1, leg)]
			}
			fLeg[leg][0] = msm1(fwAff[0], col)
			fLeg[leg][1] = msm1(fwAff[1], col)
		}
	}
	var ywAff bn254.G1Affine
	ywAff.FromJacobian(&yw)

	// Read G2 section length and stream G2 (plain) then G2a (alpha) sequentially off disk!
	n2, err := readU32()
	if err != nil {
		return nil, rep, err
	}
	if n2 != l.lenG2() {
		return nil, rep, fmt.Errorf("ciphertext G2 count %d does not match layout %d", n2, l.lenG2())
	}

	xiOth := make([]fr.Element, len(xi))
	copy(xiOth, xi)
	xiOth[0].SetZero()
	rawG2 := make([]byte, streamG2Batch*bn254.SizeOfG2AffineCompressed)
	ptsG2 := make([]bn254.G2Affine, streamG2Batch)
	g2Checker := newG2SubgroupChecker(n2, workers)

	readG2Count := func(total int, onBatch func(baseIdx int, pts []bn254.G2Affine)) error {
		done := 0
		for done < total {
			cnt := min(streamG2Batch, total-done)
			buf := rawG2[:cnt*bn254.SizeOfG2AffineCompressed]
			if err := readExact(buf); err != nil {
				return err
			}
			if err := decodeG2Chunk(buf, cnt, ptsG2[:cnt]); err != nil {
				return err
			}
			if g2Checker.bucketed {
				var addOK bool
				var addWg sync.WaitGroup
				addWg.Add(1)
				go func() {
					defer addWg.Done()
					addOK = g2Checker.Add(ptsG2[:cnt])
				}()
				onBatch(done, ptsG2[:cnt])
				addWg.Wait()
				if !addOK {
					return fmt.Errorf("invalid G2 point: subgroup check failed")
				}
			} else {
				if !g2Checker.Add(ptsG2[:cnt]) {
					return fmt.Errorf("invalid G2 point: subgroup check failed")
				}
				onBatch(done, ptsG2[:cnt])
			}
			done += cnt
		}
		return nil
	}

	// Precompute flattened tie + cross scalar vector matching layout order.
	bSc := make([]fr.Element, 0, 3*(n-1)+crossFamilies*(2*n-1))
	for a := 0; a < 3; a++ {
		bSc = append(bSc, pad(x0[a], n-1)...)
	}
	for fam := 0; fam < crossFamilies; fam++ {
		bSc = append(bSc, pad(xc[fam], 2*n-1)...)
	}

	hwWorkers := workers
	if g2Checker.bucketed && workers > g2SubgroupTrials {
		hwWorkers = workers - g2SubgroupTrials
	}

	streamComb := func() (lambda, psi bn254.GT, err error) {
		g2Checker.Reset()
		hw := make([][2]bn254.G2Jac, par.legs())
		localHw := make([][][2]bn254.G2Jac, hwWorkers)
		for wk := range localHw {
			localHw[wk] = make([][2]bn254.G2Jac, par.legs())
		}
		// 2a. h(leg, j, 0..1) — parallel G2 witness accumulation across workers.
		if err = readG2Count(2*par.legs()*n1Count, func(baseIdx int, pts []bn254.G2Affine) {
			cnt := len(pts)
			if hwWorkers <= 1 || cnt < 512 {
				for off, pt := range pts {
					idx := baseIdx + off
					coord := idx & 1
					pairIdx := idx >> 1
					leg := pairIdx / n1Count
					j := pairIdx % n1Count
					if w[j] {
						hw[leg][coord].AddMixed(&pt)
					}
				}
				return
			}
			chunk := (cnt + hwWorkers - 1) / hwWorkers
			var wg sync.WaitGroup
			for wk := 0; wk < hwWorkers; wk++ {
				lo := wk * chunk
				hi := min(cnt, lo+chunk)
				if lo >= hi {
					break
				}
				wg.Add(1)
				go func(wk, lo, hi int) {
					defer wg.Done()
					loc := localHw[wk]
					for off := lo; off < hi; off++ {
						idx := baseIdx + off
						coord := idx & 1
						pairIdx := idx >> 1
						leg := pairIdx / n1Count
						j := pairIdx % n1Count
						if w[j] {
							loc[leg][coord].AddMixed(&pts[off])
						}
					}
				}(wk, lo, hi)
			}
			wg.Wait()
		}); err != nil {
			return
		}
		for wk := range localHw {
			for leg := 0; leg < par.legs(); leg++ {
				hw[leg][0].AddAssign(&localHw[wk][leg][0])
				hw[leg][1].AddAssign(&localHw[wk][leg][1])
			}
		}
		localHw = nil

		// 2b. s(leg)
		sPts := make([]bn254.G2Affine, par.legs())
		if err = readG2Count(par.legs(), func(baseIdx int, pts []bn254.G2Affine) {
			copy(sPts[baseIdx:], pts)
		}); err != nil {
			return
		}
		// 2c. bquo(cell, j)
		bquoKey := make([]bn254.G2Affine, l.jQuo)
		bquoOthJac := make([]bn254.G2Jac, l.jQuo)
		if err = readG2Count(l.jQuo*cells, func(baseIdx int, pts []bn254.G2Affine) {
			pos := 0
			for pos < len(pts) {
				abs := baseIdx + pos
				j := abs / cells
				cel := abs % cells
				take := min(len(pts)-pos, cells-cel)
				if cel == 0 {
					bquoKey[j].ScalarMultiplication(&pts[pos], xiKey.BigInt(new(big.Int)))
				}
				subOth := msm2(pts[pos:pos+take], xiOth[cel:cel+take])
				bquoOthJac[j].AddMixed(&subOth)
				pos += take
			}
		}); err != nil {
			return
		}
		// 2d. brem(cell, j)
		bremJac := make([]bn254.G2Jac, l.jRem)
		if err = readG2Count(l.jRem*cells, func(baseIdx int, pts []bn254.G2Affine) {
			pos := 0
			for pos < len(pts) {
				abs := baseIdx + pos
				j := abs / cells
				cel := abs % cells
				take := min(len(pts)-pos, cells-cel)
				subRem := msm2(pts[pos:pos+take], xi[cel:cel+take])
				bremJac[j].AddMixed(&subRem)
				pos += take
			}
		}); err != nil {
			return
		}
		// 2e. tie + cross
		var bwJac bn254.G2Jac
		if err = readG2Count(len(bSc), func(baseIdx int, pts []bn254.G2Affine) {
			subB := msm2(pts, bSc[baseIdx:baseIdx+len(pts)])
			bwJac.AddMixed(&subB)
		}); err != nil {
			return
		}
		if !g2Checker.Finalize() {
			err = fmt.Errorf("invalid G2 point: subgroup check failed")
			return
		}

		// Batch-convert all accumulated G2 Jacobians to affine in one inversion.
		hwFlat := make([]bn254.G2Jac, 0, 2*par.legs()+l.jQuo+l.jRem+1)
		for leg := 0; leg < par.legs(); leg++ {
			hwFlat = append(hwFlat, hw[leg][0], hw[leg][1])
		}
		hwFlat = append(hwFlat, bquoOthJac...)
		hwFlat = append(hwFlat, bremJac...)
		hwFlat = append(hwFlat, bwJac)
		hwAffAll := batchJacobianToAffineG2(hwFlat)

		ps := make([]bn254.G1Affine, 0, 2*par.legs()+2*l.jQuo+l.jRem+1)
		qs := make([]bn254.G2Affine, 0, 2*par.legs()+2*l.jQuo+l.jRem+1)
		psiP := make([]bn254.G1Affine, 0, par.legs())
		psiQ := make([]bn254.G2Affine, 0, par.legs())
		off := 0
		for leg := 0; leg < par.legs(); leg++ {
			ps = append(ps, fLeg[leg][0], fLeg[leg][1])
			qs = append(qs, hwAffAll[off], hwAffAll[off+1])
			off += 2
			psiP = append(psiP, fLeg[leg][0])
			psiQ = append(psiQ, sPts[leg])
		}
		sub := func(p bn254.G1Affine, q bn254.G2Affine) {
			p.Neg(&p)
			ps = append(ps, p)
			qs = append(qs, q)
		}
		for j := 0; j < l.jQuo; j++ {
			sub(pKey[j], bquoKey[j])
			sub(pOth[j], hwAffAll[off+j])
		}
		off += l.jQuo
		for j := 0; j < l.jRem; j++ {
			sub(pRem[j], hwAffAll[off+j])
		}
		off += l.jRem
		sub(ywAff, hwAffAll[off])

		// Run the two multi-pairings concurrently.
		var errL, errP error
		var pwg sync.WaitGroup
		pwg.Add(2)
		go func() {
			defer pwg.Done()
			lambda, errL = bn254.Pair(ps, qs)
		}()
		go func() {
			defer pwg.Done()
			psi, errP = bn254.Pair(psiP, psiQ)
		}()
		pwg.Wait()
		if errL != nil {
			err = errL
			return
		}
		err = errP
		return
	}

	lambda, psi, err := streamComb()
	if err != nil {
		return nil, rep, err
	}
	lambdaA, psiA, err := streamComb()
	if err != nil {
		return nil, rep, err
	}
	g2Checker = nil
	rawG2, ptsG2 = nil, nil
	rep.PairingsDur = time.Since(tPair)

	// Lines 8-11: identical outward search and key recovery to dec().
	tSearch := time.Now()
	cw := centerBig(N, par.G, w)
	q := fr.Modulus()
	gtExp := func(x *bn254.GT, k *big.Int) bn254.GT {
		var out bn254.GT
		out.Exp(*x, new(big.Int).Mod(k, q))
		return out
	}
	xiKeyInt := xiKey.BigInt(new(big.Int))
	t1 := gtExp(&ka, new(big.Int).Neg(xiKeyInt))
	t2 := gtExp(&psiA, new(big.Int).Neg(cw))
	var target bn254.GT
	target.Mul(&lambdaA, &t1)
	target.Mul(&target, &t2)
	bound := new(big.Int).Mul(big.NewInt(int64(N)+1), big.NewInt(par.G+1))

	var t *big.Int
	var ok bool
	var sStats SearchStats
	if par.Fast {
		t, ok, sStats = searchOutwardSignFP64(&psiA, &target, bound, N, par.G)
	} else {
		t, ok, sStats = searchBigWithStats(&psiA, &target, bound)
	}
	sStats.Center = new(big.Int).Set(cw)
	rep.Search = sStats
	rep.SearchDur = time.Since(tSearch)
	if !ok {
		rep.TotalDur = time.Since(totalStart)
		return nil, rep, ErrFailed
	}

	rw := new(big.Int).Add(cw, t)
	rep.Search.SecretSum = new(big.Int).Set(rw)
	t3 := gtExp(&psi, new(big.Int).Neg(rw))
	var key bn254.GT
	key.Mul(&lambda, &t3)
	var xiInv fr.Element
	xiInv.Inverse(&xiKey)
	key = gtExp(&key, xiInv.BigInt(new(big.Int)))
	rep.TotalDur = time.Since(totalStart)
	return xor(encMsg, keyPadFor(&key, len(encMsg), par.SignClassKDF)), rep, nil
}
