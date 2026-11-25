package poly

import (
	"math/big"
	"math/bits"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const maxTwoAdicity = 28

var (
	fftOnce       sync.Once
	omegaTable    [maxTwoAdicity + 1]fr.Element // omegaTable[k] has exact order 2^k
	omegaInvTable [maxTwoAdicity + 1]fr.Element
)

func initFFT() {
	fftOnce.Do(func() {
		qm1 := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
		exp := new(big.Int).Rsh(qm1, maxTwoAdicity)
		half := new(big.Int).Lsh(big.NewInt(1), maxTwoAdicity-1)
		var c, w, check fr.Element
		for u := uint64(2); ; u++ {
			c.SetUint64(u)
			w.Exp(c, exp)
			if check.Exp(w, half); !check.IsOne() {
				break
			}
		}
		omegaTable[maxTwoAdicity] = w
		for k := maxTwoAdicity; k > 0; k-- {
			omegaTable[k-1].Square(&omegaTable[k])
		}
		for k := 0; k <= maxTwoAdicity; k++ {
			omegaInvTable[k].Inverse(&omegaTable[k])
		}
	})
}

// RootOfUnity2Pow returns a deterministic primitive 2^k-th root of unity in F_q*,
// compatible across all radix-2 FFT routines (0 <= k <= 28).
func RootOfUnity2Pow(k int) fr.Element {
	initFFT()
	return omegaTable[k]
}

// BitReverse reverses the low width bits of x.
func BitReverse(x, width int) int {
	if width <= 0 {
		return 0
	}
	return int(bits.Reverse64(uint64(x)) >> (64 - width))
}

func fftPow2Workers(n int) (workers, logW int) {
	maxW := runtime.NumCPU()
	if maxW < 2 || n < 4096 {
		return 1, 0
	}
	workers = 1
	logW = 0
	for workers*2 <= maxW && (n/(workers*2)) >= 1024 {
		workers *= 2
		logW++
	}
	return workers, logW
}

// FFT performs an in-place radix-2 NTT (forward when inv is false, inverse when
// inv is true) on a slice whose length is a power of two <= 2^28.
func FFT(a []fr.Element, inv bool) {
	n := len(a)
	if n <= 1 {
		return
	}
	initFFT()
	logN := bits.TrailingZeros(uint(n))
	for i := 0; i < n; i++ {
		j := BitReverse(i, logN)
		if i < j {
			a[i], a[j] = a[j], a[i]
		}
	}

	table := &omegaTable
	if inv {
		table = &omegaInvTable
	}

	workers, logW := fftPow2Workers(n)
	if workers == 1 {
		var w, u, v fr.Element
		for s := 1; s <= logN; s++ {
			m := 1 << s
			half := m >> 1
			wlen := table[s]
			for k := 0; k < n; k += m {
				w.SetOne()
				for j := 0; j < half; j++ {
					u = a[k+j]
					v.Mul(&a[k+j+half], &w)
					a[k+j].Add(&u, &v)
					a[k+j+half].Sub(&u, &v)
					w.Mul(&w, &wlen)
				}
			}
		}
		if inv {
			var nInv fr.Element
			nInv.SetUint64(uint64(n))
			nInv.Inverse(&nInv)
			for i := range a {
				a[i].Mul(&a[i], &nInv)
			}
		}
		return
	}

	// Stages 1..(logN - logW): each of the W contiguous sub-blocks of size n/W is
	// completely independent, running cache-locally in a single parallel pass.
	localStages := logN - logW
	blockSize := n >> logW
	var wg sync.WaitGroup
	wg.Add(workers)
	for wk := 0; wk < workers; wk++ {
		base := wk * blockSize
		go func(base int) {
			defer wg.Done()
			sub := a[base : base+blockSize]
			var w, u, v fr.Element
			for s := 1; s <= localStages; s++ {
				m := 1 << s
				half := m >> 1
				wlen := table[s]
				for k := 0; k < blockSize; k += m {
					w.SetOne()
					for j := 0; j < half; j++ {
						u = sub[k+j]
						v.Mul(&sub[k+j+half], &w)
						sub[k+j].Add(&u, &v)
						sub[k+j+half].Sub(&u, &v)
						w.Mul(&w, &wlen)
					}
				}
			}
		}(base)
	}
	wg.Wait()

	// Final logW stages: parallelize butterflies across workers inside each large block.
	for s := localStages + 1; s <= logN; s++ {
		m := 1 << s
		half := m >> 1
		wlen := table[s]
		numBlocks := n / m
		chunk := (half + workers - 1) / workers
		wg.Add(workers)
		for wk := 0; wk < workers; wk++ {
			jLo := wk * chunk
			jHi := min(half, jLo+chunk)
			go func(jLo, jHi int) {
				defer wg.Done()
				if jLo >= jHi {
					return
				}
				var wStart, w, u, v fr.Element
				wStart.Exp(wlen, big.NewInt(int64(jLo)))
				for b := 0; b < numBlocks; b++ {
					k := b * m
					w = wStart
					for j := jLo; j < jHi; j++ {
						u = a[k+j]
						v.Mul(&a[k+j+half], &w)
						a[k+j].Add(&u, &v)
						a[k+j+half].Sub(&u, &v)
						w.Mul(&w, &wlen)
					}
				}
			}(jLo, jHi)
		}
		wg.Wait()
	}

	if inv {
		var nInv fr.Element
		nInv.SetUint64(uint64(n))
		nInv.Inverse(&nInv)
		wg.Add(workers)
		for wk := 0; wk < workers; wk++ {
			lo := wk * blockSize
			hi := lo + blockSize
			go func(lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					a[i].Mul(&a[i], &nInv)
				}
			}(lo, hi)
		}
		wg.Wait()
	}
}

// EvalSubgroupBitRev evaluates p (of degree < size, or reduced mod X^size - 1)
// at all powers of RootOfUnity2Pow(log2(size)) in bit-reversed order.
func EvalSubgroupBitRev(p Poly, size int) []fr.Element {
	logN := bits.TrailingZeros(uint(size))
	buf := make([]fr.Element, size)
	for i, c := range p {
		buf[i%size].Add(&buf[i%size], &c)
	}
	FFT(buf, false)
	for i := 0; i < size; i++ {
		j := BitReverse(i, logN)
		if i < j {
			buf[i], buf[j] = buf[j], buf[i]
		}
	}
	return buf
}

// InterpSubgroupBitRev interpolates the polynomial of degree < size taking the
// given values on the powers of RootOfUnity2Pow(log2(size)) in bit-reversed order.
func InterpSubgroupBitRev(valsBitRev []fr.Element) Poly {
	size := len(valsBitRev)
	logN := bits.TrailingZeros(uint(size))
	buf := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		buf[BitReverse(i, logN)] = valsBitRev[i]
	}
	FFT(buf, true)
	return Poly(buf)
}

// Derivative returns the formal derivative p'(X).
func (p Poly) Derivative() Poly {
	if len(p) <= 1 {
		return nil
	}
	out := make(Poly, len(p)-1)
	var kElem fr.Element
	for k := 1; k < len(p); k++ {
		kElem.SetUint64(uint64(k))
		out[k-1].Mul(&p[k], &kElem)
	}
	return out
}

// DivLinear divides p by (X - root) in O(deg p) time using Horner synthetic division.
// When p(root) == 0, the returned quotient satisfies q(X) * (X - root) == p(X) identically.
func DivLinear(p Poly, root fr.Element) Poly {
	p = p.Trim()
	if len(p) <= 1 {
		return nil
	}
	n := len(p) - 1
	q := make(Poly, n)
	q[n-1] = p[n]
	var t fr.Element
	for k := n - 2; k >= 0; k-- {
		t.Mul(&q[k+1], &root)
		q[k].Add(&p[k+1], &t)
	}
	return q.Trim()
}

// MulFFT multiplies two polynomials in O(n log n) field operations via FFT,
// falling back to schoolbook multiplication for small inputs.
func MulFFT(a, b Poly) Poly {
	a, b = a.Trim(), b.Trim()
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	if len(a) < 24 || len(b) < 24 {
		return Mul(a, b)
	}
	need := len(a) + len(b) - 1
	size := 1
	for size < need {
		size <<= 1
	}
	fa := make([]fr.Element, size)
	fb := make([]fr.Element, size)
	copy(fa, a)
	copy(fb, b)
	FFT(fa, false)
	FFT(fb, false)
	if workers, _ := fftPow2Workers(size); workers > 1 {
		chunk := size / workers
		var wg sync.WaitGroup
		wg.Add(workers)
		for wk := 0; wk < workers; wk++ {
			lo := wk * chunk
			hi := lo + chunk
			go func(lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					fa[i].Mul(&fa[i], &fb[i])
				}
			}(lo, hi)
		}
		wg.Wait()
	} else {
		for i := 0; i < size; i++ {
			fa[i].Mul(&fa[i], &fb[i])
		}
	}
	FFT(fa, true)
	return Poly(fa[:need]).Trim()
}

// FromRootsFFT builds prod_{p in points} (X - p) via a subproduct tree of FFT
// multiplications in O(n log^2 n) operations, parallelizing independent tree pairs.
func FromRootsFFT(points []fr.Element) Poly {
	if len(points) == 0 {
		var one fr.Element
		one.SetOne()
		return Poly{one}
	}
	if len(points) < 32 {
		return FromRoots(points)
	}
	var one fr.Element
	one.SetOne()
	layer := make([]Poly, len(points))
	for i := range points {
		var neg fr.Element
		neg.Neg(&points[i])
		layer[i] = Poly{neg, one}
	}
	workers := runtime.NumCPU()
	for len(layer) > 1 {
		pairs := len(layer) / 2
		nextLen := (len(layer) + 1) / 2
		next := make([]Poly, nextLen)
		if workers > 1 && pairs >= 64 && len(layer[0]) < 4096 {
			w := min(workers, pairs)
			chunk := (pairs + w - 1) / w
			var wg sync.WaitGroup
			for wk := 0; wk < w; wk++ {
				lo := wk * chunk
				hi := min(pairs, lo+chunk)
				if lo >= hi {
					break
				}
				wg.Add(1)
				go func(lo, hi int) {
					defer wg.Done()
					for i := lo; i < hi; i++ {
						next[i] = MulFFT(layer[2*i], layer[2*i+1])
					}
				}(lo, hi)
			}
			wg.Wait()
		} else {
			for i := 0; i < pairs; i++ {
				next[i] = MulFFT(layer[2*i], layer[2*i+1])
			}
		}
		if len(layer)%2 == 1 {
			next[nextLen-1] = layer[len(layer)-1]
		}
		layer = next
	}
	return layer[0]
}

// InvertSeries computes f(X)^-1 mod X^prec (assuming f[0] != 0) via Newton iteration.
func InvertSeries(f Poly, prec int) Poly {
	if prec <= 0 {
		return nil
	}
	var g0, two fr.Element
	g0.Inverse(&f[0])
	two.SetUint64(2)
	g := Poly{g0}
	for cur := 1; cur < prec; cur <<= 1 {
		next := min(cur<<1, prec)
		fPref := f
		if len(fPref) > next {
			fPref = fPref[:next]
		}
		prod := MulFFT(fPref, g)
		if len(prod) > next {
			prod = prod[:next]
		}
		// twoMinus = 2 - f * g (mod X^next)
		twoMinus := make(Poly, next)
		for i := 0; i < len(prod); i++ {
			twoMinus[i].Neg(&prod[i])
		}
		twoMinus[0].Add(&twoMinus[0], &two)
		g = MulFFT(g, twoMinus)
		if len(g) > next {
			g = g[:next]
		}
	}
	return g
}

// DivModFFT divides a by nonzero b in O(n log n) field operations via Hensel /
// Newton power-series inversion of reversed polynomials.
func DivModFFT(a, b Poly) (q, r Poly) {
	b = b.Trim()
	if len(b) == 0 {
		panic("poly: division by zero")
	}
	a = a.Trim()
	if len(a) < len(b) {
		out := make(Poly, len(a))
		copy(out, a)
		return nil, out
	}
	if len(b) == 1 {
		var inv fr.Element
		inv.Inverse(&b[0])
		return Scale(a, &inv).Trim(), nil
	}
	if len(a)-len(b) < 48 {
		q, r = DivMod(a, b)
		return q.Trim(), r
	}
	m := len(a) - 1
	k := len(b) - 1
	d := m - k + 1

	revA := make(Poly, d)
	for i := 0; i < d; i++ {
		revA[i] = a[m-i]
	}
	revBLen := min(len(b), d)
	revB := make(Poly, revBLen)
	for i := 0; i < revBLen; i++ {
		revB[i] = b[k-i]
	}
	invRevB := InvertSeries(revB, d)
	return DivModWithInv(a, b, invRevB)
}

// DivModWithInv divides a by nonzero b using a precomputed series inverse
// invRevB = rev(b)^{-1} mod X^d (where d >= deg(a) - deg(b) + 1), avoiding Newton inversion.
func DivModWithInv(a, b, invRevB Poly) (q, r Poly) {
	b = b.Trim()
	if len(b) == 0 {
		panic("poly: division by zero")
	}
	a = a.Trim()
	if len(a) < len(b) {
		out := make(Poly, len(a))
		copy(out, a)
		return nil, out
	}
	if len(b) == 1 {
		var inv fr.Element
		inv.Inverse(&b[0])
		return Scale(a, &inv).Trim(), nil
	}
	m := len(a) - 1
	k := len(b) - 1
	d := m - k + 1
	revA := make(Poly, d)
	for i := 0; i < d; i++ {
		revA[i] = a[m-i]
	}
	invPref := invRevB
	if len(invPref) > d {
		invPref = invPref[:d]
	}
	revQ := MulFFT(revA, invPref)
	q = make(Poly, d)
	for i := 0; i < d && i < len(revQ); i++ {
		q[d-1-i] = revQ[i]
	}
	q = q.Trim()
	r = Sub(a, MulFFT(q, b)).Trim()
	return q, r
}
