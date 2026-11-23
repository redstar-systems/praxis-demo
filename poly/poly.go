// Package poly is plain polynomial arithmetic over the scalar field of BN254.
// Everything is quadratic time: the demo's polynomials have a few hundred
// coefficients, and the fast transforms the paper uses would only hide the
// algebra.
package poly

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// Poly holds coefficients from the constant term up.
type Poly []fr.Element

// Trim drops leading zero coefficients.
func (p Poly) Trim() Poly {
	n := len(p)
	for n > 0 && p[n-1].IsZero() {
		n--
	}
	return p[:n]
}

// Coeff returns the coefficient of X^k, zero past the end.
func (p Poly) Coeff(k int) fr.Element {
	if k < len(p) {
		return p[k]
	}
	return fr.Element{}
}

func Add(a, b Poly) Poly {
	if len(a) < len(b) {
		a, b = b, a
	}
	out := make(Poly, len(a))
	copy(out, a)
	for i := range b {
		out[i].Add(&out[i], &b[i])
	}
	return out
}

func Sub(a, b Poly) Poly {
	n := max(len(a), len(b))
	out := make(Poly, n)
	copy(out, a)
	for i := range b {
		out[i].Sub(&out[i], &b[i])
	}
	return out
}

func Mul(a, b Poly) Poly {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	out := make(Poly, len(a)+len(b)-1)
	var t fr.Element
	for i := range a {
		if a[i].IsZero() {
			continue
		}
		for j := range b {
			t.Mul(&a[i], &b[j])
			out[i+j].Add(&out[i+j], &t)
		}
	}
	return out
}

// Scale returns c*p.
func Scale(p Poly, c *fr.Element) Poly {
	out := make(Poly, len(p))
	for i := range p {
		out[i].Mul(&p[i], c)
	}
	return out
}

// Eval returns p(x).
func (p Poly) Eval(x *fr.Element) fr.Element {
	var acc fr.Element
	for i := len(p) - 1; i >= 0; i-- {
		acc.Mul(&acc, x)
		acc.Add(&acc, &p[i])
	}
	return acc
}

// Substitute returns p(cX): coefficient k is multiplied by c^k.
func (p Poly) Substitute(c *fr.Element) Poly {
	out := make(Poly, len(p))
	var pow fr.Element
	pow.SetOne()
	for i := range p {
		out[i].Mul(&p[i], &pow)
		pow.Mul(&pow, c)
	}
	return out
}

// DivMod divides a by a nonzero b and returns the quotient and remainder.
func DivMod(a, b Poly) (q, r Poly) {
	b = b.Trim()
	if len(b) == 0 {
		panic("poly: division by zero")
	}
	r = make(Poly, len(a))
	copy(r, a)
	if len(a) < len(b) {
		return nil, r.Trim()
	}
	q = make(Poly, len(a)-len(b)+1)
	var lead, t fr.Element
	lead.Inverse(&b[len(b)-1])
	for i := len(a) - len(b); i >= 0; i-- {
		q[i].Mul(&r[i+len(b)-1], &lead)
		if q[i].IsZero() {
			continue
		}
		for j := range b {
			t.Mul(&q[i], &b[j])
			r[i+j].Sub(&r[i+j], &t)
		}
	}
	return q, r.Trim()
}

// FromRoots returns the monic polynomial that vanishes exactly on the points.
func FromRoots(points []fr.Element) Poly {
	out := make(Poly, 1, len(points)+1)
	out[0].SetOne()
	var t fr.Element
	for _, p := range points {
		out = append(out, fr.Element{})
		for i := len(out) - 1; i > 0; i-- {
			t.Mul(&out[i], &p)
			out[i].Sub(&out[i-1], &t)
		}
		out[0].Mul(&out[0], &p)
		out[0].Neg(&out[0])
	}
	return out
}

// Weights returns, for each point p, 1 / prod over the other points p' of
// (p - p'): the barycentric weights for interpolation on the points.
func Weights(points []fr.Element) []fr.Element {
	w := make([]fr.Element, len(points))
	var d fr.Element
	for i := range points {
		w[i].SetOne()
		for j := range points {
			if i != j {
				d.Sub(&points[i], &points[j])
				w[i].Mul(&w[i], &d)
			}
		}
	}
	return fr.BatchInvert(w)
}

// Interpolate returns the polynomial of degree below len(points) that takes
// the given values on the distinct points. weights is Weights(points).
func Interpolate(points, weights, values []fr.Element) Poly {
	n := len(points)
	master := FromRoots(points)
	out := make(Poly, n)
	quot := make(Poly, n)
	var c, t fr.Element
	for i := 0; i < n; i++ {
		if values[i].IsZero() {
			continue
		}
		// quot = master / (X - points[i]), by synthetic division.
		quot[n-1] = master[n]
		for k := n - 2; k >= 0; k-- {
			t.Mul(&quot[k+1], &points[i])
			quot[k].Add(&master[k+1], &t)
		}
		c.Mul(&values[i], &weights[i])
		for k := 0; k < n; k++ {
			t.Mul(&quot[k], &c)
			out[k].Add(&out[k], &t)
		}
	}
	return out
}
