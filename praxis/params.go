// Package praxis is a demonstration of the Praxis witness encryption scheme
// (Tse, Vanjani, Vesely, ePrint 2026/2971), following the paper's full
// specification (Figures 9 and 10) with one chunk of powers (J = J' = 1).
//
// It is not secure. The parameters are far below the paper's, nothing here
// runs in constant time, and no part has been reviewed.
package praxis

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Params are the scheme's parameters apart from the system's shape.
type Params struct {
	DR     int   // degree of the ring R_q = F_q[Y]/(Y^DR + 1)
	K      int   // rows of the ring matrix; there are n = (K+1)*DR forms
	K1     int   // left legs
	K2     int   // right legs of each kind; K1*K2 = n/2
	G      int64 // range of each secret integer
	J            int   // chunks of quotient powers (0 means 1)
	JPrime       int   // chunks of remainder powers, dividing nc (0 means 1)
	Fast         bool  // bit-reversed H, radix-2 FFTs, and outward sign-class fingerprint search
	SignClassKDF bool  // derive message pad from {V, V^-1} via V.C0 (Section 6.4 / Praxis/Keys.lean)
}

// Toy is the default: eight forms, twelve copies of the table, and secret
// integers of 20 bits. The paper's instantiation has 4,608 forms, 6,912
// copies, and integers of about 50 bits.
var Toy = Params{DR: 2, K: 3, K1: 2, K2: 2, G: 1 << 20}

// Advanced exercises the paper's full Section 4.4, 5.1, and 5.2 mechanisms at
// interactive local scale: 24 forms (non-power-of-two n = 24 dividing q-1),
// 36 cells in a 4x9 grid, 24-bit secret integers, chunked quotient and
// remainder powers (J = 4, J' = 2), bit-reversed subgroup FFTs, and outward
// GT sign-class search with 64-bit F_{p^6} fingerprints.
var Advanced = Params{DR: 4, K: 5, K1: 4, K2: 3, G: 1 << 24, J: 4, JPrime: 2, Fast: true}

// NForms is n, the number of forms and the degree of the extension field.
func (p Params) NForms() int { return (p.K + 1) * p.DR }

// Cells is the number of copies of the table, 3n/2.
func (p Params) Cells() int { return 3 * p.K1 * p.K2 }

// JQuo returns J, defaulting 0 to 1.
func (p Params) JQuo() int {
	if p.J <= 0 {
		return 1
	}
	return p.J
}

// JRem returns J', defaulting 0 to 1.
func (p Params) JRem() int {
	if p.JPrime <= 0 {
		return 1
	}
	return p.JPrime
}

func isPow2(x int) bool { return x > 0 && x&(x-1) == 0 }

func dividesQm1(n int) bool {
	qm1 := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	return new(big.Int).Mod(qm1, big.NewInt(int64(n))).Sign() == 0
}

func primeFactors(n int) []int {
	var pf []int
	for d := 2; d*d <= n; d++ {
		if n%d == 0 {
			pf = append(pf, d)
			for n%d == 0 {
				n /= d
			}
		}
	}
	if n > 1 {
		pf = append(pf, n)
	}
	return pf
}

// Validate checks the conditions the paper puts on the parameters (Sections 3.4,
// 5.1, and 5.2): DR is a power of two, n = (K+1)*DR >= 4 is even and divides
// q - 1, K1*K2 = n/2, G >= 1, and chunk counts are non-negative.
func (p Params) Validate() error {
	switch {
	case !isPow2(p.DR) || p.DR > 1<<20:
		return fmt.Errorf("DR must be a power of two at most 2^20")
	case p.K < 1 || p.K > 1<<20:
		return fmt.Errorf("K must be from 1 to 2^20")
	}
	n := p.NForms()
	switch {
	case n < 4 || n > 1<<20 || n%2 != 0 || !dividesQm1(n):
		return fmt.Errorf("n = (K+1)*DR must be an even divisor of q-1 from 4 to 2^20")
	case p.K1 < 1 || p.K2 < 1 || p.K1 > n/2 || p.K2 > n/2 || p.K1*p.K2 != n/2:
		return fmt.Errorf("K1*K2 must equal n/2 = %d", n/2)
	case p.G < 1 || p.G > 1<<54:
		return fmt.Errorf("G must be from 1 to 2^54")
	case p.J < 0 || p.J > 1<<20 || p.JPrime < 0 || p.JPrime > 1<<20:
		return fmt.Errorf("chunk counts J and JPrime must be from 0 to 2^20")
	}
	return nil
}

// field describes F_{q^n} = F_q[T]/(T^n - c0).
type field struct {
	n     int
	c0    fr.Element // non-p-th-power for every prime p | n, so T^n - c0 is irreducible
	omega fr.Element // c0^((q-1)/n), of order n: Frobenius maps T to omega*T
}

func newField(n int) field {
	qm1 := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	factors := primeFactors(n)
	exps := make([]*big.Int, len(factors))
	for i, pf := range factors {
		exps[i] = new(big.Int).Div(qm1, big.NewInt(int64(pf)))
	}
	f := field{n: n}
	var t fr.Element
searchC0:
	for c := uint64(2); ; c++ {
		f.c0.SetUint64(c)
		for _, exp := range exps {
			if t.Exp(f.c0, exp); t.IsOne() {
				continue searchC0
			}
		}
		break
	}
	f.omega.Exp(f.c0, new(big.Int).Div(qm1, big.NewInt(int64(n))))
	return f
}

// rootOfUnity returns an element of order exactly size, a power of two.
func rootOfUnity(size int) fr.Element {
	qm1 := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	e := new(big.Int).Div(qm1, big.NewInt(int64(size)))
	half := big.NewInt(int64(size / 2))
	var c, h, t fr.Element
	for i := uint64(2); ; i++ {
		c.SetUint64(i)
		h.Exp(c, e)
		if size == 1 {
			return h
		}
		if t.Exp(h, half); !t.IsOne() {
			return h
		}
	}
}

// pow returns x^k for a small non-negative k.
func pow(x *fr.Element, k int) fr.Element {
	var out fr.Element
	out.Exp(*x, big.NewInt(int64(k)))
	return out
}
