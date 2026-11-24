package poly

import (
	"math/big"
	"math/bits"
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
	var w, u, v fr.Element
	for s := 1; s <= logN; s++ {
		m := 1 << s
		half := m >> 1
		wlen := omegaTable[s]
		if inv {
			wlen = omegaInvTable[s]
		}
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
	out := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		out[i] = buf[BitReverse(i, logN)]
	}
	return out
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
	for i := 0; i < size; i++ {
		fa[i].Mul(&fa[i], &fb[i])
	}
	FFT(fa, true)
	return Poly(fa[:need]).Trim()
}

// FromRootsFFT builds prod_{p in points} (X - p) via a subproduct tree of FFT
// multiplications in O(n log^2 n) operations.
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
	for len(layer) > 1 {
		next := make([]Poly, 0, (len(layer)+1)/2)
		for i := 0; i+1 < len(layer); i += 2 {
			next = append(next, MulFFT(layer[i], layer[i+1]))
		}
		if len(layer)%2 == 1 {
			next = append(next, layer[len(layer)-1])
		}
		layer = next
	}
	return layer[0]
}

// invertSeries computes f(X)^-1 mod X^prec (assuming f[0] != 0) via Newton iteration.
func invertSeries(f Poly, prec int) Poly {
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
	invRevB := invertSeries(revB, d)
	revQ := MulFFT(revA, invRevB)
	q = make(Poly, d)
	for i := 0; i < d && i < len(revQ); i++ {
		q[d-1-i] = revQ[i]
	}
	q = q.Trim()
	r = Sub(a, MulFFT(q, b)).Trim()
	return q, r
}
