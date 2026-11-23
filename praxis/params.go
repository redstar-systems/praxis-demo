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
	DR int   // degree of the ring R_q = F_q[Y]/(Y^DR + 1)
	K  int   // rows of the ring matrix; there are n = (K+1)*DR forms
	K1 int   // left legs
	K2 int   // right legs of each kind; K1*K2 = n/2
	G  int64 // range of each secret integer
}

// Toy is the default: eight forms, twelve copies of the table, and secret
// integers of 20 bits. The paper's instantiation has 4,608 forms, 6,912
// copies, and integers of about 50 bits.
var Toy = Params{DR: 2, K: 3, K1: 2, K2: 2, G: 1 << 20}

// NForms is n, the number of forms and the degree of the extension field.
func (p Params) NForms() int { return (p.K + 1) * p.DR }

// Cells is the number of copies of the table, 3n/2.
func (p Params) Cells() int { return 3 * p.K1 * p.K2 }

func isPow2(x int) bool { return x > 0 && x&(x-1) == 0 }

// Validate checks the conditions the paper puts on the parameters, and one
// of the demo's own: n is a power of two, which makes T^n - c0 irreducible
// for any non-square c0.
func (p Params) Validate() error {
	n := p.NForms()
	switch {
	case !isPow2(p.DR):
		return fmt.Errorf("DR must be a power of two")
	case p.K < 1:
		return fmt.Errorf("K must be at least 1")
	case !isPow2(n) || n < 4 || n > 1<<20:
		return fmt.Errorf("n = (K+1)*DR must be a power of two from 4 to 2^20")
	case p.K1 < 1 || p.K2 < 1 || p.K1*p.K2 != n/2:
		return fmt.Errorf("K1*K2 must equal n/2 = %d", n/2)
	case p.G < 1 || p.G > 1<<40:
		return fmt.Errorf("G must be from 1 to 2^40")
	}
	return nil
}

// field describes F_{q^n} = F_q[T]/(T^n - c0).
type field struct {
	n     int
	c0    fr.Element // non-square, so T^n - c0 is irreducible
	omega fr.Element // c0^((q-1)/n), of order n: Frobenius maps T to omega*T
}

func newField(n int) field {
	qm1 := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	half := new(big.Int).Rsh(qm1, 1)
	f := field{n: n}
	var t fr.Element
	for c := uint64(2); ; c++ {
		f.c0.SetUint64(c)
		if t.Exp(f.c0, half); !t.IsOne() {
			break
		}
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
