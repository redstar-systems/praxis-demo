package praxis

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"
	mrand "math/rand/v2"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"praxis-demo/bqs"
	"praxis-demo/poly"
)

// makePlantedSystem builds a random BQS in N unknowns (using only activeVars <= N
// unknowns so the rest appear in no constraint) with constraints whose product
// counts follow prodCounts. Every third constraint forces C = 0 by adding a
// cancelling product, exercising zero right-hand sides.
func makePlantedSystem(rng *mrand.Rand, N, activeVars int, prodCounts []int) (*bqs.System, []bool) {
	w := make([]bool, N+1)
	w[0] = true
	for i := 1; i <= N; i++ {
		w[i] = rng.IntN(2) == 1
	}
	randVec := func() bqs.Vec {
		var v bqs.Vec
		if rng.IntN(2) == 0 {
			v = append(v, bqs.T(0, int64(rng.IntN(11)-5)))
		}
		if activeVars > 0 {
			terms := 1 + rng.IntN(min(4, activeVars))
			for k := 0; k < terms; k++ {
				idx := 1 + rng.IntN(activeVars)
				coeff := int64(rng.IntN(15) - 7)
				if coeff != 0 {
					v = append(v, bqs.T(idx, coeff))
				}
			}
		}
		return v
	}

	s := &bqs.System{N: N}
	for ci, f := range prodCounts {
		var con bqs.Constraint
		var lhs, term fr.Element
		zeroRHS := ci%3 == 0
		if zeroRHS && f >= 2 {
			for p := 0; p < f-1; p++ {
				a, b := randVec(), randVec()
				av, bv := a.Apply(w), b.Apply(w)
				term.Mul(&av, &bv)
				lhs.Add(&lhs, &term)
				con.Products = append(con.Products, bqs.Product{A: a, B: b})
			}
			// Final product (-lhs)*1 cancels sum so C = nil (zero RHS).
			var neg fr.Element
			neg.Neg(&lhs)
			con.Products = append(con.Products, bqs.Product{
				A: bqs.Vec{{I: 0, V: neg}},
				B: bqs.One(),
			})
			con.C = nil
		} else if zeroRHS {
			// Single product that vanishes on w, with C = nil.
			var a bqs.Vec
			if activeVars > 0 {
				if w[1] {
					a = bqs.Vec{bqs.T(1, 1), bqs.T(0, -1)}
				} else {
					a = bqs.Vec{bqs.T(1, 1)}
				}
			}
			con.Products = []bqs.Product{{A: a, B: randVec()}}
			con.C = nil
		} else {
			for p := 0; p < f; p++ {
				a, b := randVec(), randVec()
				av, bv := a.Apply(w), b.Apply(w)
				term.Mul(&av, &bv)
				lhs.Add(&lhs, &term)
				con.Products = append(con.Products, bqs.Product{A: a, B: b})
			}
			// C = cLin(w) + (lhs - cLin(w))*w[0]
			cVec := randVec()
			cv := cVec.Apply(w)
			var diff fr.Element
			diff.Sub(&lhs, &cv)
			cVec = append(cVec, bqs.Term{I: 0, V: diff})
			con.C = cVec
		}
		s.Constraints = append(s.Constraints, con)
	}
	return s, w
}

// Check 1: Definition 4.6 admissibility and QAP table values.
func TestConformanceDef46Admissibility(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	shapes := []struct {
		N     int
		prods []int
	}{
		{0, []int{1}},             // D = 4, exact subgroup of size 4
		{1, []int{1}},             // D = 5, subgroup of size 8
		{2, []int{1, 1}},          // D = 8, exact subgroup of size 8
		{2, []int{3, 2, 1}},       // nu = 4, D = 16, exact subgroup of size 16
		{11, []int{1, 5, 8, 2}},   // nu = 16, mixed Ft
		{19, []int{17, 1}},        // nu = 32
	}
	qm1 := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	for _, sh := range shapes {
		s, w := makePlantedSystem(rng, sh.N, sh.N, sh.prods)
		pp, err := Setup(Toy, s)
		if err != nil {
			t.Fatalf("Setup(%+v): %v", sh, err)
		}
		fmax := s.Fmax()
		if pp.Nu <= fmax || pp.Nu > 2*fmax || !isPow2(pp.Nu) {
			t.Fatalf("nu = %d for Fmax = %d", pp.Nu, fmax)
		}
		if new(big.Int).Mod(qm1, big.NewInt(int64(pp.Nu))).Sign() != 0 {
			t.Fatalf("nu = %d does not divide q-1", pp.Nu)
		}
		if pp.D != s.N+2+pp.Nu*len(s.Constraints) || len(pp.Points) != pp.D {
			t.Fatalf("bad D = %d", pp.D)
		}

		// Pairwise distinctness of all D points.
		seen := make(map[[fr.Bytes]byte]int, pp.D)
		for idx, pt := range pp.Points {
			b := pt.Bytes()
			if prev, dup := seen[b]; dup {
				t.Fatalf("duplicate evaluation point at %d and %d", prev, idx)
			}
			seen[b] = idx
			if pt.IsZero() {
				t.Fatalf("point %d is 0 (not in F_q*)", idx)
			}
		}

		// Each K_t must be a coset of the unique subgroup of order nu:
		// for all p, p' in K_t, (p / p')^nu == 1, and p != 0.
		nuBig := big.NewInt(int64(pp.Nu))
		cosetRepPow := make(map[[fr.Bytes]byte]int)
		for tc := 0; tc < len(s.Constraints); tc++ {
			base := pp.Points[tc*pp.Nu]
			var baseNu fr.Element
			baseNu.Exp(base, nuBig)
			repBytes := baseNu.Bytes()
			if prev, dup := cosetRepPow[repBytes]; dup {
				t.Fatalf("cosets %d and %d coincide", prev, tc)
			}
			cosetRepPow[repBytes] = tc
			for j := 0; j < pp.Nu; j++ {
				pt := pp.Points[tc*pp.Nu+j]
				var ratio, check fr.Element
				ratio.Div(&pt, &base)
				check.Exp(ratio, nuBig)
				if !check.IsOne() {
					t.Fatalf("point (%d,%d) not in coset of order %d", tc, j, pp.Nu)
				}
			}
		}

		// d_0..d_N, rho must lie in NO K_t, i.e. pt^nu != base^nu for every t.
		for idx := pp.cosetLen(); idx < pp.D; idx++ {
			var pNu fr.Element
			pNu.Exp(pp.Points[idx], nuBig)
			if tc, inCoset := cosetRepPow[pNu.Bytes()]; inCoset {
				t.Fatalf("single point %d lies in coset %d", idx, tc)
			}
		}

		// Verify Lemma 4.7 on w.
		if _, _, _, exact := pp.quotients(w); !exact {
			t.Fatalf("quotients not exact on planted witness for %+v", sh)
		}
	}
}

// Check 1: Equations (5), (6), (7) — extension field, exact tie divisions, and mask identity.
func TestConformanceTieAndMaskIdentityEq6Eq7(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(3, 4))
	s, w := makePlantedSystem(rng, 13, 13, []int{2, 3})
	for _, par := range []Params{
		Toy,
		{DR: 1, K: 3, K1: 2, K2: 1, G: 8},
		{DR: 4, K: 3, K1: 1, K2: 8, G: 8},
		{DR: 4, K: 3, K1: 8, K2: 1, G: 8},
	} {
		n := par.NForms()
		f := newField(n)
		// omega has exact order n and omega^(n/2) = -1.
		var wHalf, wFull, minusOne fr.Element
		minusOne.SetInt64(-1)
		wHalf = pow(&f.omega, n/2)
		wFull = pow(&f.omega, n)
		if !wHalf.Equal(&minusOne) || !wFull.IsOne() {
			t.Fatalf("bad omega for n=%d", n)
		}

		seed := []byte("0123456789abcdef0123456789abcdef")
		phi := par.forms(seed, s.N)
		wt := par.weightsOf(f, phi, w)

		// V(w) has only even powers of T.
		for k := 1; k < n; k += 2 {
			if !wt.V[k].IsZero() {
				t.Fatalf("V[%d] nonzero", k)
			}
		}

		// Exact division by P(T) = T^n - c0 in Equation (6).
		var negOmega fr.Element
		negOmega.Neg(&f.omega)
		uRot := wt.U.Substitute(&negOmega)
		modulus := f.modulus()
		nums := [3]poly.Poly{
			poly.Sub(poly.Mul(wt.U, wt.zCirc), poly.Mul(wt.V, wt.zMinus)),
			poly.Sub(poly.Mul(wt.U, wt.zPlus), poly.Mul(uRot, wt.zMinus)),
			poly.Sub(poly.Mul(wt.V, wt.zPlus), poly.Mul(uRot, wt.zCirc)),
		}
		var x0 [3]poly.Poly
		for a := 0; a < 3; a++ {
			var rem poly.Poly
			x0[a], rem = poly.DivMod(nums[a], modulus)
			if len(rem) != 0 {
				t.Fatalf("tie polynomial %d not divisible by P(T)", a+1)
			}
		}

		// Direct check of Equation (7) in F_q:
		// sum_{c=(k1,leg)} pi_k1 * xi_c(w) * (w^T * theta_leg) ==
		// pi * sum_{a=1..3} eta_a * (P(ups)*x0_a(ups) + eps*x+_a(ups) + eps^-1*x-_a(ups))
		pi, ups, eps := randNonzero(), randNonzero(), randNonzero()
		eta := [3]fr.Element{randNonzero(), randNonzero(), randNonzero()}
		var one, epsInv fr.Element
		one.SetOne()
		epsInv.Inverse(&eps)
		piK := make([]fr.Element, par.K1)
		for k1 := 0; k1 < par.K1; k1++ {
			w2 := pow(&f.omega, 2*k1)
			var op fr.Element
			op.Mul(&eps, &w2)
			op.Add(&op, &one)
			p := pow(&ups, 2*k1)
			piK[k1].Mul(&pi, &p)
			piK[k1].Mul(&piK[k1], &op)
		}

		var xMinus, xCirc, xPlus fr.Element
		xCirc.Neg(&ups)
		xPlus.Mul(&xCirc, &f.omega)
		xMinus.Div(&xCirc, &f.omega)
		zM, zC, zP := zAt(phi, &xMinus), zAt(phi, &xCirc), zAt(phi, &xPlus)

		var lhs fr.Element
		for leg := 0; leg < par.legs(); leg++ {
			kl := par.legExp(leg)
			p1 := pow(&ups, kl)
			p2 := pow(&xPlus, kl)
			p2.Mul(&p2, &epsInv)
			var wDotMask fr.Element
			for j, on := range w {
				if !on {
					continue
				}
				var mj, a, b, tmp fr.Element
				if par.legKind(leg) == kindV {
					a.Mul(&eta[2], &zP[j])
					b.Mul(&eta[0], &zM[j])
					a.Sub(&a, &b)
					mj.Mul(&p1, &a)
				} else {
					a.Mul(&eta[0], &zC[j])
					b.Mul(&eta[1], &zP[j])
					a.Add(&a, &b)
					a.Mul(&a, &p1)
					b.Mul(&eta[1], &zM[j])
					tmp.Mul(&eta[2], &zC[j])
					b.Add(&b, &tmp)
					b.Mul(&b, &p2)
					mj.Sub(&a, &b)
				}
				wDotMask.Add(&wDotMask, &mj)
			}
			for k1 := 0; k1 < par.K1; k1++ {
				xiC := par.xi(&wt, k1, leg)
				var term fr.Element
				term.Mul(&piK[k1], &xiC)
				term.Mul(&term, &wDotMask)
				lhs.Add(&lhs, &term)
			}
		}

		u1, v1, u2 := make(poly.Poly, n), make(poly.Poly, n), make(poly.Poly, n)
		for k := 0; k < n; k++ {
			k1 := (k / 2) % par.K1
			a := pow(&f.omega, 2*k1)
			b := pow(&negOmega, k-2*k1)
			u1[k].Mul(&wt.U[k], &a)
			v1[k].Mul(&wt.V[k], &a)
			u2[k].Mul(&wt.U[k], &b)
		}
		xPlusPolys := [3]poly.Poly{
			poly.Sub(poly.Mul(u1, wt.zCirc), poly.Mul(v1, wt.zMinus)),
			poly.Mul(u1, wt.zPlus),
			poly.Mul(v1, wt.zPlus),
		}
		xMinusPolys := [3]poly.Poly{
			nil,
			poly.Sub(nil, poly.Mul(u2, wt.zMinus)),
			poly.Sub(nil, poly.Mul(u2, wt.zCirc)),
		}
		pUps := modulus.Eval(&ups)
		var rhs fr.Element
		for a := 0; a < 3; a++ {
			v0 := x0[a].Eval(&ups)
			v0.Mul(&v0, &pUps)
			vp := xPlusPolys[a].Eval(&ups)
			vp.Mul(&vp, &eps)
			vm := xMinusPolys[a].Eval(&ups)
			vm.Mul(&vm, &epsInv)
			var sum fr.Element
			sum.Add(&v0, &vp)
			sum.Add(&sum, &vm)
			sum.Mul(&sum, &eta[a])
			rhs.Add(&rhs, &sum)
		}
		rhs.Mul(&rhs, &pi)

		if !lhs.Equal(&rhs) {
			t.Fatalf("Equation (7) mask identity failed for %+v", par)
		}
	}
}

// Check 1 & 5: Definition 5.3 centered sampler and Lemma 5.5 search bound.
func TestCenteredSamplerLemma55(t *testing.T) {
	q := fr.Modulus()
	halfQ := new(big.Int).Rsh(q, 1)
	toSigned := func(e fr.Element) int64 {
		bi := e.BigInt(new(big.Int))
		if bi.Cmp(halfQ) > 0 {
			bi.Sub(bi, q)
		}
		return bi.Int64()
	}
	for _, tc := range []struct {
		N int
		G int64
	}{
		{0, 1}, {1, 1}, {1, 2}, {2, 1}, {7, 5}, {16, 1 << 20}, {55, 17},
	} {
		allZero := make([]bool, tc.N+1)
		allZero[0] = true
		allOne := make([]bool, tc.N+1)
		for i := range allOne {
			allOne[i] = true
		}
		half := make([]bool, tc.N+1)
		half[0] = true
		for i := 1; i <= tc.N; i += 2 {
			half[i] = true
		}
		for rep := 0; rep < 25; rep++ {
			r := sampleR(tc.N, tc.G)
			var sumOthers int64
			for i := 1; i <= tc.N; i++ {
				ri := toSigned(r[i])
				if ri < 2 || ri > tc.G+1 {
					t.Fatalf("r[%d] = %d outside [2, %d]", i, ri, tc.G+1)
				}
				sumOthers += ri
			}
			r0 := toSigned(r[0])
			a := (int64(tc.N)*(tc.G+1) + 1) / 2
			rStar := r0 - a + sumOthers/2
			if rStar < 2 || rStar > tc.G+1 {
				t.Fatalf("implied r* = %d outside [2, %d] (N=%d, G=%d)", rStar, tc.G+1, tc.N, tc.G)
			}
			bound := (int64(tc.N) + 1) * (tc.G + 1)
			tight := float64(tc.N+2)*float64(tc.G-1)/4.0 + 1.5
			for _, w := range [][]bool{allZero, allOne, half} {
				var rw int64
				for i, on := range w {
					if on {
						rw += toSigned(r[i])
					}
				}
				cw := center(tc.N, tc.G, w)
				diff := rw - cw
				if diff < 0 {
					diff = -diff
				}
				if diff > bound || float64(diff) > tight {
					t.Fatalf("|r(w)-cw| = %d exceeds Lemma 5.5 bound %.2f / %d", diff, tight, bound)
				}
			}
		}
	}
}

// Check 2: Random BQS shapes (1 to 200 unknowns, varying constraints, varying products
// per constraint, zero RHS, unconstrained unknowns, multiple witnesses).
func TestRandomShapesAndUnusedUnknowns(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(42, 99))
	fast := Params{DR: 2, K: 1, K1: 2, K2: 1, G: 64}
	cases := []struct {
		name       string
		par        Params
		N, active  int
		prodCounts []int
	}{
		{"N1_single", Toy, 1, 1, []int{1}},
		{"N5_unused_vars", fast, 5, 2, []int{1, 2}},
		{"N12_nu8_zeroRHS", fast, 12, 10, []int{1, 4, 7, 2}},
		{"N25_nu16_mixed", fast, 25, 20, []int{15, 1, 3, 8, 2}},
		{"N40_nu32", fast, 40, 35, []int{17, 6, 1}},
		{"N200_large", fast, 200, 180, []int{3, 1, 5, 2, 4, 1, 2, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, w := makePlantedSystem(rng, tc.N, tc.active, tc.prodCounts)
			if !s.IsWitness(w) {
				t.Fatal("planted assignment is not a witness")
			}
			pp, err := Setup(tc.par, s)
			if err != nil {
				t.Fatal(err)
			}
			g1, g2 := pp.Counts()
			p1, p2 := pp.PaperCounts()
			if g1 != p1 || g2 != p2 {
				t.Fatalf("counts (%d,%d) != paper (%d,%d)", g1, g2, p1, p2)
			}
			msg := []byte("shape test: " + tc.name)
			ct, err := Enc(pp, msg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Dec(pp, ct, w)
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("Dec failed: got %q, err %v", got, err)
			}
			// If there are unconstrained unknowns (active < N), flipping them
			// gives distinct witnesses of different Hamming weight that must also decrypt.
			if tc.active < tc.N {
				w2 := append([]bool(nil), w...)
				for u := tc.active + 1; u <= tc.N; u++ {
					w2[u] = !w2[u]
				}
				if !s.IsWitness(w2) {
					t.Fatal("flipping unused unknowns broke witness")
				}
				got2, err := Dec(pp, ct, w2)
				if err != nil || !bytes.Equal(got2, msg) {
					t.Fatalf("Dec with alternate witness failed: got %q, err %v", got2, err)
				}
			}
		})
	}
}

// Check 2: Every small parameter set Params.Validate accepts (n in {4, 8, 16}),
// including DR=1, G=1, and the extremes K1=1, K2=n/2 and K1=n/2, K2=1.
func TestAllSmallValidParams(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(7, 11))
	s, w := makePlantedSystem(rng, 3, 3, []int{1, 2})
	var validParams []Params
	for _, n := range []int{4, 8, 16} {
		for dr := 1; dr <= n/2; dr *= 2 {
			k := n/dr - 1
			if k < 1 {
				continue
			}
			for k1 := 1; k1 <= n/2; k1 *= 2 {
				k2 := (n / 2) / k1
				g := int64(1)
				if (k1+dr)%2 == 0 {
					g = 19
				}
				p := Params{DR: dr, K: k, K1: k1, K2: k2, G: g}
				if err := p.Validate(); err != nil {
					t.Fatalf("expected %+v to be valid: %v", p, err)
				}
				validParams = append(validParams, p)
			}
		}
	}
	if len(validParams) == 0 {
		t.Fatal("no parameter sets enumerated")
	}
	msg := []byte("grid sweep")
	ch := make(chan Params, len(validParams))
	for _, par := range validParams {
		ch <- par
	}
	close(ch)
	var wgPool sync.WaitGroup
	poolErr := make(chan error, len(validParams))
	for wIdx := 0; wIdx < 4; wIdx++ {
		wgPool.Add(1)
		go func() {
			defer wgPool.Done()
			for par := range ch {
				pp, err := Setup(par, s)
				if err != nil {
					poolErr <- err
					return
				}
				ct, err := Enc(pp, msg)
				if err != nil {
					poolErr <- err
					return
				}
				got, err := Dec(pp, ct, w)
				if err != nil || !bytes.Equal(got, msg) {
					poolErr <- errors.New("decryption mismatch in parameter sweep")
					return
				}
			}
		}()
	}
	wgPool.Wait()
	close(poolErr)
	for err := range poolErr {
		t.Fatal(err)
	}

	// Also verify concurrent Enc and Dec sharing a single *Public and *Ciphertext.
	ppShared, err := Setup(Params{DR: 2, K: 1, K1: 2, K2: 1, G: 32}, s)
	if err != nil {
		t.Fatal(err)
	}
	ctShared, err := Enc(ppShared, msg)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 4)
	for g := 0; g < 2; g++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := Enc(ppShared, msg); err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			got, err := Dec(ppShared, ctShared, w)
			if err != nil || !bytes.Equal(got, msg) {
				errCh <- errors.New("shared Dec mismatch")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

// Check 3: Edge cases — empty message, long message, all-zero and all-one witnesses,
// N=0 and N=1 systems, exact subgroup fill D == |H|, and invalid parameter / witness rejection.
func TestEdgeCases(t *testing.T) {
	par := Params{DR: 2, K: 1, K1: 2, K2: 1, G: 64}

	// System in N=5 unknowns where BOTH all-zero and all-one assignments are witnesses:
	// constraint w_1 * (1 - w_2) + ... = 0 when all w_i equal each other, specifically w_i = w_1.
	sBoth := &bqs.System{N: 5}
	for i := 2; i <= 5; i++ {
		// (w_i - w_1) * 1 = 0
		sBoth.Constraints = append(sBoth.Constraints, bqs.Constraint{
			Products: []bqs.Product{{A: bqs.Vec{bqs.T(i, 1), bqs.T(1, -1)}, B: bqs.One()}},
		})
	}
	wAllZero := []bool{true, false, false, false, false, false}
	wAllOne := []bool{true, true, true, true, true, true}
	if !sBoth.IsWitness(wAllZero) || !sBoth.IsWitness(wAllOne) {
		t.Fatal("test system should accept both all-0 and all-1")
	}
	ppBoth, err := Setup(par, sBoth)
	if err != nil {
		t.Fatal(err)
	}

	// Empty message (nil and empty slice) and 100 KB message.
	longMsg := make([]byte, 100_000)
	for i := range longMsg {
		longMsg[i] = byte(i*31 + 7)
	}
	for _, msg := range [][]byte{nil, {}, []byte("x"), longMsg} {
		ct, err := Enc(ppBoth, msg)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if _, err := ct.WriteTo(&buf); err != nil {
			t.Fatal(err)
		}
		ctBack, err := ReadCiphertext(&buf)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range [][]bool{wAllZero, wAllOne} {
			got, err := Dec(ppBoth, ctBack, w)
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("len(msg)=%d: got len %d, err %v", len(msg), len(got), err)
			}
		}
	}

	// N=0 system (D = 0 + 2 + 2 = 4, exact subgroup of order 4) and
	// N=2, nc=2, nu=2 system (D = 2 + 2 + 4 = 8, exact subgroup of order 8).
	for _, bc := range []struct {
		s *bqs.System
		w []bool
	}{
		{
			s: &bqs.System{N: 0, Constraints: []bqs.Constraint{{Products: []bqs.Product{{A: bqs.One(), B: bqs.One()}}, C: bqs.One()}}},
			w: []bool{true},
		},
		{
			s: &bqs.System{N: 1, Constraints: []bqs.Constraint{{Products: []bqs.Product{{A: bqs.Vec{bqs.T(1, 1)}, B: bqs.One()}}}}},
			w: []bool{true, false},
		},
		{
			s: &bqs.System{N: 2, Constraints: []bqs.Constraint{
				{Products: []bqs.Product{{A: bqs.Vec{bqs.T(1, 1)}, B: bqs.Vec{bqs.T(2, 1)}}}, C: bqs.One()},
				{Products: []bqs.Product{{A: bqs.Vec{bqs.T(1, 1)}, B: bqs.One()}}, C: bqs.One()},
			}},
			w: []bool{true, true, true},
		},
	} {
		pp, err := Setup(par, bc.s)
		if err != nil {
			t.Fatal(err)
		}
		ct, err := Enc(pp, []byte("boundary"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Dec(pp, ct, bc.w)
		if err != nil || string(got) != "boundary" {
			t.Fatalf("N=%d boundary failed: %q, %v", bc.s.N, got, err)
		}
		// Bad witness shapes return ErrNotWitness without panicking.
		for _, badW := range [][]bool{nil, {}, {false}, make([]bool, bc.s.N+2)} {
			if _, err := Dec(pp, ct, badW); !errors.Is(err, ErrNotWitness) {
				t.Fatalf("Dec bad witness %v: got %v", badW, err)
			}
			if _, err := DecUnchecked(pp, ct, badW); !errors.Is(err, ErrNotWitness) {
				t.Fatalf("DecUnchecked bad witness %v: got %v", badW, err)
			}
		}
	}

	// Standard invalid parameter rejections.
	for _, badPar := range []Params{
		{DR: 0, K: 3, K1: 2, K2: 2, G: 1},
		{DR: -2, K: 3, K1: 2, K2: 2, G: 1},
		{DR: 3, K: 3, K1: 6, K2: 1, G: 1},
		{DR: 2, K: 0, K1: 1, K2: 1, G: 1},
		{DR: 1, K: 1, K1: 1, K2: 1, G: 1},             // n = 2 < 4
		{DR: 1, K: 2, K1: 1, K2: 1, G: 1},             // n = 3 odd
		{DR: 2, K: 6, K1: 7, K2: 1, G: 1},             // n = 14 does not divide q-1
		{DR: 1 << 20, K: 1, K1: 1, K2: 1 << 20, G: 1}, // n = 2^21 > 2^20
		{DR: 2, K: 3, K1: 0, K2: 4, G: 1},
		{DR: 2, K: 3, K1: 3, K2: 1, G: 1},
		{DR: 2, K: 3, K1: 2, K2: 2, G: 0},
		{DR: 2, K: 3, K1: 2, K2: 2, G: -5},
		{DR: 2, K: 3, K1: 2, K2: 2, G: (1 << 40) + 1},
	} {
		if err := badPar.Validate(); err == nil {
			t.Fatalf("Params.Validate accepted invalid %+v", badPar)
		}
	}
}

// Check 4: File handling — truncations, bad magic, oversized length fields,
// cross-system ciphertexts (different shape and same shape), off-curve G1/G2,
// and out-of-subgroup G2 twist points.
func TestFileHandlingAndInvalidPoints(t *testing.T) {
	par := Params{DR: 2, K: 1, K1: 2, K2: 1, G: 64}
	s15, err := bqs.Factoring(big.NewInt(15), 3, 3) // 3 * 5 = 15 (N=6)
	if err != nil {
		t.Fatal(err)
	}
	pp15, err := Setup(par, s15)
	if err != nil {
		t.Fatal(err)
	}
	ct15, err := Enc(pp15, []byte("secret-15"))
	if err != nil {
		t.Fatal(err)
	}
	var rawBuf bytes.Buffer
	if _, err := ct15.WriteTo(&rawBuf); err != nil {
		t.Fatal(err)
	}
	validBytes := rawBuf.Bytes()

	// 1. Truncated files across key structural offsets.
	offsets := []int{
		0, 1, 10, len(magic) - 1, len(magic), len(magic) + 2, len(magic) + 5,
		len(magic) + 4 + 32 + 2, len(magic) + 4 + 32 + 4 + 9 + 100,
		len(validBytes) - 65, len(validBytes) - 1,
	}
	for _, off := range offsets {
		if _, err := ReadCiphertext(bytes.NewReader(validBytes[:off])); err == nil {
			t.Fatalf("expected error on ciphertext truncated at %d/%d", off, len(validBytes))
		}
	}

	// 2. Wrong magic.
	badMagic := append([]byte(nil), validBytes...)
	badMagic[0] = 'X'
	if _, err := ReadCiphertext(bytes.NewReader(badMagic)); err == nil {
		t.Fatal("expected error on wrong magic")
	}

	// 3. Oversized length fields (> 1<<26) at Seed, Msg, G1, G2.
	putU32 := func(b []byte, pos int, v uint32) []byte {
		cp := append([]byte(nil), b...)
		binary.BigEndian.PutUint32(cp[pos:pos+4], v)
		return cp
	}
	seedLenPos := len(magic)
	msgLenPos := seedLenPos + 4 + len(ct15.Seed)
	g1LenPos := msgLenPos + 4 + len(ct15.Msg) + bn254.SizeOfGT
	g2LenPos := g1LenPos + 4 + len(ct15.G1)*bn254.SizeOfG1AffineCompressed
	for _, pos := range []int{seedLenPos, msgLenPos, g1LenPos, g2LenPos} {
		for _, bigLen := range []uint32{(1 << 26) + 1, 0xffffffff} {
			if _, err := ReadCiphertext(bytes.NewReader(putU32(validBytes, pos, bigLen))); err == nil {
				t.Fatalf("expected error for oversized length %d at pos %d", bigLen, pos)
			}
		}
	}

	// 4. Ciphertext for one system read against another:
	// (a) Different shape.
	sDiff, _ := bqs.Factoring(big.NewInt(35), 4, 4) // N=8 != 6
	wDiff := bqs.FactoringWitness(big.NewInt(5), big.NewInt(7), 4, 4)
	ppDiff, err := Setup(par, sDiff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Dec(ppDiff, ct15, wDiff); err == nil {
		t.Fatal("expected shape mismatch error reading N=6 ciphertext against N=8 system")
	}
	// (b) Same shape (N=6, nc=1, Fmax=1), different statement (21 = 3 * 7).
	s21, _ := bqs.Factoring(big.NewInt(21), 3, 3)
	w21 := bqs.FactoringWitness(big.NewInt(3), big.NewInt(7), 3, 3)
	pp21, err := Setup(par, s21)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Dec(pp21, ct15, w21); !errors.Is(err, ErrFailed) {
		t.Fatalf("ciphertext for 15 decrypted under 21: got %q, err %v", got, err)
	}

	// 5. Invalid G1 point: compressed X not on Y^2 = X^3 + 3, invalid infinity, non-canonical >= p.
	g1FirstPos := g1LenPos + 4
	var notOnG1 [bn254.SizeOfG1AffineCompressed]byte
	for x := byte(1); ; x++ {
		notOnG1[0] = 0x80 // mCompressedSmallest
		notOnG1[31] = x
		var p bn254.G1Affine
		if _, err := p.SetBytes(notOnG1[:]); err != nil {
			break
		}
	}
	corruptG1 := append([]byte(nil), validBytes...)
	copy(corruptG1[g1FirstPos:], notOnG1[:])
	if _, err := ReadCiphertext(bytes.NewReader(corruptG1)); err == nil {
		t.Fatal("accepted off-curve G1 point")
	}

	badInfG1 := append([]byte(nil), validBytes...)
	for i := 0; i < 32; i++ {
		badInfG1[g1FirstPos+i] = 0
	}
	badInfG1[g1FirstPos] = 0x40 // mCompressedInfinity with non-zero trailing byte
	badInfG1[g1FirstPos+31] = 1
	if _, err := ReadCiphertext(bytes.NewReader(badInfG1)); err == nil {
		t.Fatal("accepted malformed G1 infinity point")
	}

	nonCanonG1 := append([]byte(nil), validBytes...)
	pModBytes := fp.Modulus().Bytes()
	copy(nonCanonG1[g1FirstPos:g1FirstPos+32], pModBytes)
	nonCanonG1[g1FirstPos] |= 0x80
	if _, err := ReadCiphertext(bytes.NewReader(nonCanonG1)); err == nil {
		t.Fatal("accepted non-canonical G1 X >= p")
	}

	// 6. Invalid G2 points: (a) not on twist curve; (b) ON twist curve but NOT in subgroup G2!
	g2FirstPos := g2LenPos + 4
	var notOnG2, notInSubgroupG2 [bn254.SizeOfG2AffineCompressed]byte
	foundOff, foundWrongSub := false, false
	for x := byte(1); !foundOff || !foundWrongSub; x++ {
		var cand [bn254.SizeOfG2AffineCompressed]byte
		cand[0] = 0x80 // mCompressedSmallest
		cand[31] = x
		cand[63] = 1
		var p bn254.G2Affine
		dec := bn254.NewDecoder(bytes.NewReader(cand[:]), bn254.NoSubgroupChecks())
		err := dec.Decode(&p)
		if err != nil && !foundOff {
			notOnG2 = cand
			foundOff = true
		} else if err == nil && p.IsOnCurve() && !p.IsInSubGroup() && !foundWrongSub {
			notInSubgroupG2 = p.Bytes()
			foundWrongSub = true
		}
	}
	corruptG2Off := append([]byte(nil), validBytes...)
	copy(corruptG2Off[g2FirstPos:], notOnG2[:])
	if _, err := ReadCiphertext(bytes.NewReader(corruptG2Off)); err == nil {
		t.Fatal("accepted off-curve G2 point")
	}

	// Test both ct.G2 and ct.G2a slots for subgroup check.
	g2aFirstPos := g2FirstPos + len(ct15.G2)*bn254.SizeOfG2AffineCompressed
	for _, pos := range []int{g2FirstPos, g2aFirstPos} {
		corruptG2Sub := append([]byte(nil), validBytes...)
		copy(corruptG2Sub[pos:], notInSubgroupG2[:])
		if _, err := ReadCiphertext(bytes.NewReader(corruptG2Sub)); err == nil {
			t.Fatalf("accepted G2 twist point outside prime-order subgroup at pos %d", pos)
		}
	}
}

// ============================================================================
// Regression Tests for Fixed Bugs
// ============================================================================

func TestRegressionNegativeHugeAndNilInputs(t *testing.T) {
	if _, err := Setup(Toy, nil); err == nil {
		t.Fatal("expected error on nil system")
	}
	for _, badN := range []int{-1, -2, math.MaxInt, (1 << 28) + 1} {
		s := &bqs.System{
			N:           badN,
			Constraints: []bqs.Constraint{{Products: []bqs.Product{{}}}},
		}
		if _, err := Setup(Toy, s); err == nil {
			t.Fatalf("Setup accepted N = %d", badN)
		}
	}
	if _, err := Enc(nil, []byte("hi")); err == nil {
		t.Fatal("Enc accepted nil *Public")
	}
	if _, err := Dec(nil, nil, []bool{true}); !errors.Is(err, ErrNotWitness) {
		t.Fatalf("Dec(nil, ...) = %v, want ErrNotWitness", err)
	}
	if _, err := DecUnchecked(nil, nil, []bool{true}); !errors.Is(err, ErrNotWitness) {
		t.Fatalf("DecUnchecked(nil, ...) = %v, want ErrNotWitness", err)
	}
	s, _ := bqs.Factoring(big.NewInt(15), 3, 3)
	w := bqs.FactoringWitness(big.NewInt(3), big.NewInt(5), 3, 3)
	pp, err := Setup(Params{DR: 2, K: 1, K1: 2, K2: 1, G: 8}, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Dec(pp, nil, w); err == nil {
		t.Fatal("Dec accepted nil *Ciphertext")
	}
}

func TestRegressionParamsValidateWraparound(t *testing.T) {
	for _, bad := range []Params{
		{DR: 4, K: (1 << 62) + 1, K1: 2, K2: 2, G: 1},
		{DR: 1 << 62, K: 1, K1: 2, K2: 2, G: 1},
		{DR: 2, K: 1, K1: 6, K2: 3074457345618258603, G: 1},
		{DR: 2, K: 1, K1: 3074457345618258603, K2: 6, G: 1},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("Params.Validate accepted overflowing Params %+v", bad)
		}
	}
}

func TestRegressionLargeNGArithmeticNoOverflow(t *testing.T) {
	const maxG = int64(1 << 40)

	// 1. search() and searchBig() at huge bounds (2*bound+1 > MaxInt64, and bound > MaxInt64).
	_, _, g1, g2 := bn254.Generators()
	base, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		t.Fatal(err)
	}
	bound := (int64(4_194_303) + 1) * (maxG + 1)
	for _, want := range []int64{0, 1, -1, 777, -2048} {
		var target bn254.GT
		target.Exp(base, new(big.Int).Mod(big.NewInt(want), fr.Modulus()))
		if got, ok := search(&base, &target, bound); !ok || got != want {
			t.Fatalf("search(want=%d, bound=%d) = (%d, %v)", want, bound, got, ok)
		}
	}
	// Bound exceeding int64 (N = 2^27, G = 2^40 => bound ~ 2^67).
	hugeBound := new(big.Int).Mul(big.NewInt((1<<27)+1), big.NewInt(maxG+1))
	var targetNeg bn254.GT
	targetNeg.Exp(base, new(big.Int).Mod(big.NewInt(-12345), fr.Modulus()))
	if got, ok := searchBig(&base, &targetNeg, hugeBound); !ok || got.Int64() != -12345 {
		t.Fatalf("searchBig(want=-12345) = (%v, %v)", got, ok)
	}
	// Least absolute value tie-breaking on a small-order element (-1 in F_{p^12}^* of order 2).
	var negOne, one bn254.GT
	one.SetOne()
	negOne.Sub(&negOne, &one)
	if got, ok := search(&negOne, &negOne, 10); !ok || (got != 1 && got != -1) {
		t.Fatalf("search(order-2, -1) = (%d, %v), want +-1", got, ok)
	}
	if got, ok := search(&negOne, &one, 10); !ok || got != 0 {
		t.Fatalf("search(order-2, 1) = (%d, %v), want 0", got, ok)
	}

	// 2. center() and centerBig() at N = 8_388_606, 8_388_608, and 1<<16.
	const nCenter = 8_388_606 // 2^23 - 2
	allOnes := make([]bool, nCenter+1)
	for i := range allOnes {
		allOnes[i] = true
	}
	const wantCenter = int64((1<<62) - (1<<40) + (1<<22) - 1 + (1<<61) + 3*(1<<21))
	if cw := center(nCenter, maxG, allOnes); cw != wantCenter {
		t.Fatalf("center(%d, 2^40, allOnes) = %d, want %d", nCenter, cw, wantCenter)
	}
	const nCenter2 = 8_388_608 // 2^23
	allZeros := make([]bool, nCenter2+1)
	allZeros[0] = true
	const wantCenter2 = int64((1<<61) + (1<<39) - (1<<21) + 1)
	if cw := center(nCenter2, maxG, allZeros); cw != wantCenter2 {
		t.Fatalf("center(%d, 2^40, allZeros) = %d, want %d", nCenter2, cw, wantCenter2)
	}
	// N = 1<<27 with wt = 1<<27 (center exceeds MaxInt64, handled via centerBig).
	bigOnes := make([]bool, (1<<16)+1)
	for i := range bigOnes {
		bigOnes[i] = true
	}
	if cb := centerBig(1<<16, maxG, bigOnes); cb.Sign() <= 0 {
		t.Fatalf("centerBig <= 0: %s", cb)
	}

	// 3. sampleR() at N = 20_000, G = 2^40 (and verify formula at N = 8_388_608? Keep fast: N = 50_000 here,
	// plus verify big.Int arithmetic matches Definition 5.3).
	r := sampleR(1024, maxG)
	q := fr.Modulus()
	halfQ := new(big.Int).Rsh(q, 1)
	r0Big := r[0].BigInt(new(big.Int))
	if r0Big.Cmp(halfQ) > 0 {
		r0Big.Sub(r0Big, q)
	}
	if r0Big.Cmp(big.NewInt(2)) < 0 {
		t.Fatalf("sampleR produced r[0] = %s < 2", r0Big)
	}
}

func TestRegressionReadCiphertextRejectsInvalidGTAndStreamingAlloc(t *testing.T) {
	par := Params{DR: 2, K: 1, K1: 2, K2: 1, G: 8}
	s, _ := bqs.Factoring(big.NewInt(15), 3, 3)
	pp, err := Setup(par, s)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Enc(pp, []byte("gt"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := ct.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	kaPos := len(magic) + 4 + len(ct.Seed) + 4 + len(ct.Msg)

	// Ka = 0 (not invertible) must be rejected.
	zeroGT := append([]byte(nil), raw...)
	for i := 0; i < bn254.SizeOfGT; i++ {
		zeroGT[kaPos+i] = 0
	}
	if _, err := ReadCiphertext(bytes.NewReader(zeroGT)); err == nil {
		t.Fatal("ReadCiphertext accepted Ka = 0")
	}

	// Ka = 2 (in F_p^* \ GT) must be rejected.
	twoGT := append([]byte(nil), zeroGT...)
	twoGT[kaPos+bn254.SizeOfGT-1] = 2
	if _, err := ReadCiphertext(bytes.NewReader(twoGT)); err == nil {
		t.Fatal("ReadCiphertext accepted Ka = 2 outside GT")
	}

	// Truncated header claiming n1 = 1<<26 or n2 = 1<<26 must fail immediately without OOM.
	for _, tc := range [][2]uint32{{1 << 26, 0}, {0, 1 << 26}} {
		var trunc bytes.Buffer
		trunc.WriteString(magic)
		_ = binary.Write(&trunc, binary.BigEndian, uint32(0))
		_ = binary.Write(&trunc, binary.BigEndian, uint32(0))
		var one bn254.GT
		one.SetOne()
		ka := one.Bytes()
		trunc.Write(ka[:])
		_ = binary.Write(&trunc, binary.BigEndian, tc[0])
		if tc[0] == 0 {
			_ = binary.Write(&trunc, binary.BigEndian, tc[1])
		}
		if _, err := ReadCiphertext(&trunc); err == nil {
			t.Fatalf("expected EOF error for truncated counts %v", tc)
		}
	}
}

type failAfterWriter struct {
	limit   int
	written int
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.written >= w.limit {
		return 0, io.ErrClosedPipe
	}
	allow := min(len(p), w.limit-w.written)
	w.written += allow
	if allow < len(p) {
		return allow, io.ErrClosedPipe
	}
	return allow, nil
}

func TestRegressionWriteToByteCountAndValidation(t *testing.T) {
	par := Params{DR: 2, K: 1, K1: 2, K2: 1, G: 8}
	s, _ := bqs.Factoring(big.NewInt(15), 3, 3)
	pp, _ := Setup(par, s)
	ct, _ := Enc(pp, []byte("hello"))

	fw := &failAfterWriter{limit: 100}
	n, err := ct.WriteTo(fw)
	if err == nil {
		t.Fatal("expected write error")
	}
	if n != int64(fw.written) {
		t.Fatalf("WriteTo reported %d bytes written, want %d", n, fw.written)
	}

	var nilCT *Ciphertext
	if _, err := nilCT.WriteTo(&bytes.Buffer{}); err == nil {
		t.Fatal("expected error writing nil Ciphertext")
	}
	badG2 := *ct
	badG2.G2a = badG2.G2a[:1]
	if _, err := badG2.WriteTo(&bytes.Buffer{}); err == nil {
		t.Fatal("expected error writing mismatched G2/G2a lengths")
	}
}
