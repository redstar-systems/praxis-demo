package poly

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func elem(v int64) fr.Element {
	var e fr.Element
	e.SetInt64(v)
	return e
}

func TestDegenerateZeroAndConstant(t *testing.T) {
	var zeroNil Poly
	zeroUntrimmed := Poly{elem(0), elem(0), elem(0)}
	constFive := Poly{elem(5)}
	constFiveUntrimmed := Poly{elem(5), elem(0), elem(0)}
	lin := Poly{elem(3), elem(-2)}

	for _, z := range []Poly{zeroNil, zeroUntrimmed} {
		if len(z.Trim()) != 0 {
			t.Fatalf("Trim(zero) = %v, want empty", z.Trim())
		}
		for _, k := range []int{0, 1, 5} {
			if c := z.Coeff(k); !c.IsZero() {
				t.Fatalf("zero.Coeff(%d) = %v, want 0", k, c)
			}
		}
		if !equal(Add(z, lin), lin) || !equal(Add(lin, z), lin) || !equal(Add(z, z), nil) {
			t.Fatal("Add with zero failed")
		}
		if !equal(Sub(lin, z), lin) || !equal(Sub(z, z), nil) {
			t.Fatal("Sub with zero failed")
		}
		negLin := Sub(z, lin)
		if !equal(Add(negLin, lin), nil) {
			t.Fatal("0 - lin + lin != 0")
		}
		if !equal(Mul(z, lin), nil) || !equal(Mul(lin, z), nil) || !equal(Mul(z, z), nil) {
			t.Fatal("Mul with zero failed")
		}
		c7 := elem(7)
		if !equal(Scale(z, &c7), nil) {
			t.Fatal("Scale(zero, 7) != 0")
		}
		c0 := elem(0)
		if !equal(Scale(lin, &c0), nil) {
			t.Fatal("Scale(lin, 0) != 0")
		}
		x := elem(19)
		if v := z.Eval(&x); !v.IsZero() {
			t.Fatalf("zero.Eval(19) = %v, want 0", v)
		}
		if v := z.Eval(&c0); !v.IsZero() {
			t.Fatalf("zero.Eval(0) = %v, want 0", v)
		}
		if !equal(z.Substitute(&c7), nil) || !equal(z.Substitute(&c0), nil) {
			t.Fatal("zero.Substitute != 0")
		}
	}

	for _, c := range []Poly{constFive, constFiveUntrimmed} {
		if len(c.Trim()) != 1 || !c.Trim()[0].Equal(&constFive[0]) {
			t.Fatalf("Trim(5) = %v", c.Trim())
		}
		x := elem(42)
		if got := c.Eval(&x); !got.Equal(&constFive[0]) {
			t.Fatalf("const.Eval(42) = %v, want 5", got)
		}
		s := elem(9)
		if !equal(c.Substitute(&s), constFive) {
			t.Fatal("const.Substitute changed constant")
		}
		c0 := elem(0)
		if !equal(lin.Substitute(&c0), Poly{elem(3)}) {
			t.Fatal("lin.Substitute(0) != lin(0)")
		}
	}
}

func TestDivModDegenerate(t *testing.T) {
	// Zero dividend (nil and untrimmed longer than divisor).
	b := Poly{elem(7), elem(1)}
	for _, z := range []Poly{nil, {}, {elem(0), elem(0), elem(0), elem(0)}} {
		q, r := DivMod(z, b)
		if !equal(q, nil) || len(r) != 0 {
			t.Fatalf("DivMod(0, b) = (%v, %v), want (0, 0)", q, r)
		}
	}

	// Divisor longer than dividend (trimmed and untrimmed dividend).
	short := Poly{elem(3), elem(4)}
	longDiv := Poly{elem(1), elem(2), elem(5), elem(9)}
	q, r := DivMod(short, longDiv)
	if len(q) != 0 || !equal(r, short) {
		t.Fatalf("DivMod(short, long) = (%v, %v), want (nil, short)", q, r)
	}
	untrimmedShort := Poly{elem(3), elem(4), elem(0), elem(0), elem(0)}
	q, r = DivMod(untrimmedShort, longDiv)
	if !equal(q, nil) || len(r) != 2 || !equal(r, short) {
		t.Fatalf("DivMod(untrimmedShort, long) = (%v, %v), want (0, short)", q, r)
	}

	// Division by constant (trimmed and untrimmed divisor).
	a := random(10)
	for _, div := range []Poly{{elem(5)}, {elem(5), elem(0), elem(0)}} {
		q, r := DivMod(a, div)
		if len(r) != 0 || !equal(Mul(q, div), a) {
			t.Fatal("division by constant failed")
		}
	}

	// Division by zero panics as documented.
	for _, zeroDiv := range []Poly{nil, {}, {elem(0), elem(0)}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic on division by zero")
				}
			}()
			DivMod(a, zeroDiv)
		}()
	}
}

func TestInterpolateAndRootsDegenerate(t *testing.T) {
	// 0 points.
	z0 := FromRoots(nil)
	if len(z0) != 1 || !z0[0].IsOne() {
		t.Fatalf("FromRoots(nil) = %v, want [1]", z0)
	}
	w0 := Weights(nil)
	if len(w0) != 0 {
		t.Fatalf("Weights(nil) = %v, want empty", w0)
	}
	p0 := Interpolate(nil, w0, nil)
	if len(p0) != 0 {
		t.Fatalf("Interpolate(nil) = %v, want empty", p0)
	}

	// 1 point (zero value and nonzero value).
	pts1 := []fr.Element{elem(13)}
	w1 := Weights(pts1)
	if len(w1) != 1 || !w1[0].IsOne() {
		t.Fatalf("Weights(1 pt) = %v, want [1]", w1)
	}
	z1 := FromRoots(pts1)
	if v := z1.Eval(&pts1[0]); !v.IsZero() {
		t.Fatalf("FromRoots(1 pt) at root = %v, want 0", v)
	}
	p1Zero := Interpolate(pts1, w1, []fr.Element{elem(0)})
	if !equal(p1Zero, nil) {
		t.Fatalf("Interpolate(1 pt, [0]) = %v, want 0", p1Zero)
	}
	p1Val := Interpolate(pts1, w1, []fr.Element{elem(42)})
	x := elem(99)
	if got := p1Val.Eval(&x); !got.Equal(& []fr.Element{elem(42)}[0]) {
		t.Fatalf("Interpolate(1 pt, [42])(99) = %v, want 42", got)
	}

	// Multiple points with all-zero and constant values.
	pts := []fr.Element{elem(0), elem(1), elem(-1), elem(77)}
	wts := Weights(pts)
	if !equal(Interpolate(pts, wts, make([]fr.Element, len(pts))), nil) {
		t.Fatal("Interpolate of all zeros != 0")
	}
	valsConst := []fr.Element{elem(9), elem(9), elem(9), elem(9)}
	if !equal(Interpolate(pts, wts, valsConst), Poly{elem(9)}) {
		t.Fatal("Interpolate of constant != constant")
	}
}

func TestPolyCoeffNegativeIndex(t *testing.T) {
	var p Poly
	if c := p.Coeff(-1); !c.IsZero() {
		t.Fatalf("nil.Coeff(-1) = %v, want 0", c)
	}
	q := Poly{elem(7)}
	if c := q.Coeff(-5); !c.IsZero() {
		t.Fatalf("q.Coeff(-5) = %v, want 0", c)
	}
}
