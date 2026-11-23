package praxis

import (
	"crypto/sha512"
	"encoding/binary"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"praxis-demo/poly"
)

// forms expands a seed into the ring matrix M and returns its n linear forms
// (Definition 5.1) as dense coefficient vectors of length N+1. Form 0 is the
// constant 1, forms 1..DR-1 are zero, and form i*DR+s is coefficient s of
// row i of M applied to the unknowns packed DR at a time into ring elements.
func (par Params) forms(seed []byte, N int) [][]fr.Element {
	n, dr := par.NForms(), par.DR
	ell := (N + dr - 1) / dr
	phi := make([][]fr.Element, n)
	for e := range phi {
		phi[e] = make([]fr.Element, N+1)
	}
	phi[0][0].SetOne()
	for i := 1; i <= par.K; i++ {
		for j := 0; j <= ell; j++ {
			m := ringElement(seed, i, j, dr)
			if j == 0 {
				for s := 0; s < dr; s++ {
					phi[i*dr+s][0] = m[s]
				}
				continue
			}
			// Unknown u is the coefficient of Y^t in the j-th packed
			// ring element; m * Y^t wraps around with a sign change.
			for t := 0; t < dr; t++ {
				u := (j-1)*dr + t + 1
				if u > N {
					break
				}
				for s := 0; s < dr; s++ {
					if s >= t {
						phi[i*dr+s][u] = m[s-t]
					} else {
						phi[i*dr+s][u].Neg(&m[dr+s-t])
					}
				}
			}
		}
	}
	return phi
}

// ringElement is the seed oracle: entry (i, j) of the matrix, as dr field
// elements.
func ringElement(seed []byte, i, j, dr int) []fr.Element {
	out := make([]fr.Element, dr)
	var idx [12]byte
	binary.BigEndian.PutUint32(idx[0:], uint32(i))
	binary.BigEndian.PutUint32(idx[4:], uint32(j))
	for s := range out {
		binary.BigEndian.PutUint32(idx[8:], uint32(s))
		h := sha512.New()
		h.Write([]byte("praxis-demo/seed"))
		h.Write(seed)
		h.Write(idx[:])
		out[s].SetBytes(h.Sum(nil))
	}
	return out
}

// zAt returns z[x], the vector sum over e of x^e * phi_e.
func zAt(phi [][]fr.Element, x *fr.Element) []fr.Element {
	out := make([]fr.Element, len(phi[0]))
	var p, t fr.Element
	p.SetOne()
	for e := range phi {
		for i := range out {
			t.Mul(&phi[e][i], &p)
			out[i].Add(&out[i], &t)
		}
		p.Mul(&p, x)
	}
	return out
}

// reduce reduces a polynomial in T modulo T^n - c0.
func (f field) reduce(p poly.Poly) poly.Poly {
	out := make(poly.Poly, f.n)
	var c, t fr.Element
	c.SetOne()
	for k := 0; k < len(p); k++ {
		if k > 0 && k%f.n == 0 {
			c.Mul(&c, &f.c0)
		}
		t.Mul(&p[k], &c)
		out[k%f.n].Add(&out[k%f.n], &t)
	}
	return out
}

// modulus returns T^n - c0.
func (f field) modulus() poly.Poly {
	p := make(poly.Poly, f.n+1)
	p[0].Neg(&f.c0)
	p[f.n].SetOne()
	return p
}

// weights holds what decryption derives from the forms at an assignment w.
type weights struct {
	zMinus, zCirc, zPlus poly.Poly // z(w) with T replaced by -T/omega, -T, -omega*T
	U, V                 poly.Poly // the two products, n coefficients each; V's odd ones are zero
}

func (par Params) weightsOf(f field, phi [][]fr.Element, w []bool) weights {
	n := f.n
	z := make(poly.Poly, n)
	for e := 0; e < n; e++ {
		for i, on := range w {
			if on {
				z[e].Add(&z[e], &phi[e][i])
			}
		}
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
	wt.U = f.reduce(poly.Mul(z, wt.zMinus))
	wt.V = f.reduce(poly.Mul(z, wt.zCirc))
	return wt
}

// The grid of copies. A right leg has a kind (E, O or V) and an index k2.
const (
	kindE = 0
	kindO = 1
	kindV = 2
)

func (par Params) legs() int { return 3 * par.K2 }

func (par Params) legKind(leg int) int { return leg / par.K2 }

// legExp is the exponent a right leg contributes.
func (par Params) legExp(leg int) int {
	e := 2 * par.K1 * (leg % par.K2)
	if par.legKind(leg) == kindO {
		e++
	}
	return e
}

// cell numbers the copy at left leg k1 and right leg leg. The key copy is 0.
func (par Params) cell(k1, leg int) int { return leg*par.K1 + k1 }

// xi is the weight of a cell: the coefficient of its exponent in U for E and
// O legs, in V for V legs.
func (par Params) xi(wt *weights, k1, leg int) fr.Element {
	k := 2*k1 + par.legExp(leg)
	if par.legKind(leg) == kindV {
		return wt.V[k]
	}
	return wt.U[k]
}
