package poly

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func random(n int) Poly {
	p := make(Poly, n)
	for i := range p {
		p[i].SetRandom()
	}
	return p
}

func equal(a, b Poly) bool { return len(Sub(a, b).Trim()) == 0 }

func TestDivMod(t *testing.T) {
	a, b := random(23), random(7)
	q, r := DivMod(a, b)
	if len(r) >= len(b) || !equal(Add(Mul(q, b), r), a) {
		t.Fatal("a != q*b + r")
	}
	if _, r := DivMod(Mul(a, b), b); len(r) != 0 {
		t.Fatal("exact division left a remainder")
	}
}

func TestInterpolate(t *testing.T) {
	p := random(12)
	points := make([]fr.Element, 12)
	values := make([]fr.Element, 12)
	for i := range points {
		points[i].SetUint64(uint64(3*i + 1))
		values[i] = p.Eval(&points[i])
	}
	if !equal(Interpolate(points, Weights(points), values), p) {
		t.Fatal("interpolation did not recover the polynomial")
	}
	z := FromRoots(points)
	for i := range points {
		if v := z.Eval(&points[i]); !v.IsZero() {
			t.Fatal("FromRoots does not vanish on a root")
		}
	}
}

func TestSubstitute(t *testing.T) {
	p := random(9)
	var c, x, cx fr.Element
	c.SetUint64(7)
	x.SetUint64(11)
	cx.Mul(&c, &x)
	a, b := p.Substitute(&c).Eval(&x), p.Eval(&cx)
	if !a.Equal(&b) {
		t.Fatal("p(cX) at x is not p at cx")
	}
}
