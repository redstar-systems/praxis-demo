package praxis

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"praxis-demo/bqs"
	"praxis-demo/poly"
)

// TestLeanConstantsConformance verifies that Table4 and newField(4608) match
// every constant in psivesely/praxis-lean's Praxis/Constants.lean bit-for-bit,
// including the 77-digit Frobenius generator beta and Published.lean's counts.
func TestLeanConstantsConformance(t *testing.T) {
	// Exact constants from https://github.com/psivesely/praxis-lean/blob/main/Praxis/Constants.lean
	const (
		leanQ          = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
		leanBeta       = "15455056031545522072329890326622223210121953105925913337013641664433101999706"
		leanN          = 4608
		leanM          = 2304
		leanC0         = 5
		leanRingDegree = 64
		leanModuleRows = 71
		leanK1         = 192
		leanK2         = 12
		leanMq         = 11
		leanWr         = 11
		leanGBits      = 51
		leanU          = 2048
		leanVars       = 391693
		leanGates      = 1694
	)

	if gotQ := fr.Modulus().String(); gotQ != leanQ {
		t.Fatalf("scalar field modulus q = %s, want Praxis/Constants.lean %s", gotQ, leanQ)
	}
	if Table4.DR != leanRingDegree || Table4.K != leanModuleRows ||
		Table4.NForms() != leanN || Table4.NForms()/2 != leanM ||
		Table4.K1 != leanK1 || Table4.K2 != leanK2 ||
		Table4.JQuo() != leanMq || Table4.JRem() != leanWr {
		t.Fatalf("Table4 parameters %+v do not match Praxis/Constants.lean", Table4)
	}
	if gotBits := big.NewInt(Table4G).BitLen(); gotBits != leanGBits {
		t.Fatalf("Table4G bit length = %d, want Lean g_bits = %d", gotBits, leanGBits)
	}

	fld := newField(leanN)
	c0Big := fld.c0.BigInt(new(big.Int))
	if c0Big.Int64() != leanC0 {
		t.Fatalf("newField(%d).c0 = %s, want %d", leanN, c0Big, leanC0)
	}
	betaBig := fld.omega.BigInt(new(big.Int))
	if betaBig.String() != leanBeta {
		t.Fatalf("newField(%d).omega = %s, want Praxis/Constants.lean beta = %s", leanN, betaBig, leanBeta)
	}
	// Verify BetaLaws from Praxis/Kummer.lean: beta^(n/2) == -1 and orderOf(beta) == n.
	halfPow := pow(&fld.omega, leanM)
	var negOne fr.Element
	negOne.SetInt64(-1)
	if !halfPow.Equal(&negOne) {
		t.Fatalf("beta^m = %s, want -1", halfPow.String())
	}

	// Verify QAP geometry and Published.lean element counts at Groth16 circuit dimensions
	// (N = 391,693, nc = 1,694, Fmax = 2,047 -> U = 2,048).
	D := leanVars + 2 + leanU*leanGates // 3,861,007
	E1 := (D + leanMq - 1) / leanMq     // 351,001
	E1p := leanGates / leanWr           // 154
	if D != 3_861_007 || E1 != 351_001 || E1p != 154 {
		t.Fatalf("unexpected Groth16 QAP dimensions D=%d E1=%d E1p=%d", D, E1, E1p)
	}

	// Check LeanCounts against Published.lean's countG1 / countG2 formulas directly on Advanced + Toy.
	for _, par := range []Params{Toy, Advanced} {
		sys, err := bqs.Factoring(big.NewInt(15), 4, 4)
		if err != nil {
			t.Fatal(err)
		}
		pp, err := Setup(par, sys.PadConstraints(par.JRem()))
		if err != nil {
			t.Fatal(err)
		}
		gotG1, gotG2 := pp.LeanCounts()
		e1 := pp.Delta
		u := pp.Nu
		e1p := pp.DeltaPrime / pp.Nu
		legCount := 3 * par.K2
		cellCount := par.K1 * legCount
		n := par.NForms()
		wantG1 := 2*par.K1*(pp.S.N+1) + 2*par.K1 + e1 + (u-1)*e1p + (pp.S.N + 1)
		wantG2 := 2*2*legCount*(pp.S.N+1) + 2*2*legCount +
			2*cellCount*par.JQuo() + 2*cellCount*par.JRem() +
			2*legCount + 2*5*(2*n-1) + 2*3*(n-1)
		if gotG1 != wantG1 || gotG2 != wantG2 {
			t.Fatalf("LeanCounts(%+v) = (%d, %d), want Published.lean (%d, %d)", par, gotG1, gotG2, wantG1, wantG2)
		}
	}
}

// TestLeanAlgebraicAndExponentConformance translates Praxis/Forms.lean,
// Praxis/Kummer.lean, Praxis/Grid.lean, Praxis/Enc.lean, and Praxis/Dec.lean
// (instantiated with Setting.lean's expGroups = Additive F_q) directly and
// asserts exact F_q equality on every form coefficient, Kummer weight, cross
// polynomial, G1/G2/GT ciphertext exponent, and decRef pairing combination.
func TestLeanAlgebraicAndExponentConformance(t *testing.T) {
	clauses := [][3]int{{1, -2, 3}, {-1, 2, -3}, {2, 3, 4}, {-1, -3, -4}}
	rawSys, err := bqs.ThreeSAT(4, clauses)
	if err != nil {
		t.Fatal(err)
	}
	wBool := bqs.ThreeSATWitness([]bool{true, true, false, false}, clauses)

	for _, tc := range []struct {
		name string
		par  Params
	}{
		{"Toy_unchunked_n8", Toy},
		{"Advanced_chunked_Serret_n24", Advanced},
	} {
		t.Run(tc.name, func(t *testing.T) {
			par := tc.par
			sys := rawSys.PadConstraints(par.JRem())
			pp, err := Setup(par, sys)
			if err != nil {
				t.Fatal(err)
			}
			N := pp.S.N
			n := par.NForms()
			m := n / 2
			d := par.DR
			rows := par.K
			cols := (N + d - 1) / d
			beta := pp.fld.omega
			c0 := pp.fld.c0

			seed := bytes.Repeat([]byte{0x42}, 32)
			goPhi := par.forms(seed, N)

			// --- 1. Praxis/Forms.lean: rqMul, slotPoly, phi, formVec ---
			rqMul := func(a, b []fr.Element) []fr.Element {
				out := make([]fr.Element, d)
				var prod fr.Element
				for j := 0; j < d; j++ {
					for k := 0; k < d; k++ {
						prod.Mul(&a[j], &b[k])
						if j+k < d {
							out[j+k].Add(&out[j+k], &prod)
						} else {
							out[j+k-d].Sub(&out[j+k-d], &prod)
						}
					}
				}
				return out
			}
			leanPhiAt := func(e int, x []fr.Element) fr.Element {
				var zero fr.Element
				if e/d == 0 {
					if e%d == 0 {
						return x[0]
					}
					return zero
				}
				row := e/d - 1
				if row >= rows {
					return zero
				}
				s := e % d
				// In Forms.lean: FormIndex (row, none) corresponds to Go's ringElement(seed, row+1, 0, d),
				// and (row, some j) corresponds to ringElement(seed, row+1, j+1, d).
				aNone := ringElement(seed, row+1, 0, d)
				var acc fr.Element
				acc.Mul(&x[0], &aNone[s])
				for j := 0; j < cols; j++ {
					slot := make([]fr.Element, d)
					for k := 0; k < d; k++ {
						if 1+d*j+k <= N {
							slot[k] = x[1+d*j+k]
						}
					}
					aSome := ringElement(seed, row+1, j+1, d)
					prod := rqMul(aSome, slot)
					acc.Add(&acc, &prod[s])
				}
				return acc
			}
			for e := 0; e < n; e++ {
				for colIdx := 0; colIdx <= N; colIdx++ {
					unit := make([]fr.Element, N+1)
					unit[colIdx].SetOne()
					want := leanPhiAt(e, unit)
					if !goPhi[e][colIdx].Equal(&want) {
						t.Fatalf("formVec mismatch at (e=%d, c=%d): got %s, Lean %s",
							e, colIdx, goPhi[e][colIdx].String(), want.String())
					}
				}
			}

			// --- 2. Praxis/Kummer.lean & Praxis/Grid.lean: Uw, Vw, cellWeight ---
			xVec := make([]fr.Element, N+1)
			for i, bit := range wBool {
				if bit {
					xVec[i].SetOne()
				}
			}
			zOf := make([]fr.Element, n)
			for e := 0; e < n; e++ {
				for i := 0; i <= N; i++ {
					var prod fr.Element
					prod.Mul(&goPhi[e][i], &xVec[i])
					zOf[e].Add(&zOf[e], &prod)
				}
			}
			sigma := func(s int, a []fr.Element) []fr.Element {
				out := make([]fr.Element, n)
				for e := 0; e < n; e++ {
					p := pow(&beta, (s*e)%n)
					out[e].Mul(&p, &a[e])
				}
				return out
			}
			kmul := func(a, b []fr.Element) []fr.Element {
				raw := make([]fr.Element, 2*n)
				var prod fr.Element
				for i := 0; i < n; i++ {
					for j := 0; j < n; j++ {
						prod.Mul(&a[i], &b[j])
						raw[i+j].Add(&raw[i+j], &prod)
					}
				}
				out := make([]fr.Element, n)
				for e := 0; e < n; e++ {
					var hi fr.Element
					hi.Mul(&c0, &raw[e+n])
					out[e].Add(&raw[e], &hi)
				}
				return out
			}
			leanUw := kmul(zOf, sigma(m-1, zOf))
			leanVwFull := kmul(zOf, sigma(m, zOf))

			wt := par.weightsOf(pp.fld, goPhi, wBool)
			for k1 := 0; k1 < par.K1; k1++ {
				for leg := 0; leg < par.legs(); leg++ {
					gotXi := par.xi(&wt, k1, leg)
					cExp := 2*k1 + par.legExp(leg)
					var wantXi fr.Element
					if par.legKind(leg) == kindV {
						wantXi = leanVwFull[2*(cExp/2)] // Vw(cellExp / 2)
					} else {
						wantXi = leanUw[cExp]
					}
					if !gotXi.Equal(&wantXi) {
						t.Fatalf("cellWeight mismatch at (k1=%d, leg=%d): got %s, Lean %s",
							k1, leg, gotXi.String(), wantXi.String())
					}
				}
			}

			// --- 3. Praxis/Enc.lean: g1Exp, g2Exp, gtExp, kappa vs computeEncScalars ---
			r := make([]fr.Element, N+1)
			y := make([]fr.Element, N+1)
			var sumR int64
			for i := 1; i <= N; i++ {
				v := int64(2 + (i*7)%19)
				sumR += v
				r[i].SetInt64(v)
			}
			aCenter := (int64(N)*(par.G+1) + 1) / 2
			r[0].SetInt64(aCenter + 5 - sumR/2)
			for i := 0; i <= N; i++ {
				y[i].SetUint64(uint64(101 + 37*i))
			}
			fe := func(u uint64) fr.Element {
				var x fr.Element
				x.SetUint64(u)
				return x
			}
			coins := encCoins{
				r:       r,
				y:       y,
				tau:     fe(170003), // outside subgroup H
				omega12: fe(23),
				omega22: fe(29),
				alpha:   fe(31),
				pi:      fe(37),
				sKind:   [3]fr.Element{fe(41), fe(43), fe(47)},
				ups:     fe(53),
				zeta:    fe(59),
				zeta1:   fe(61),
				zeta2:   fe(67),
				eta:     [3]fr.Element{fe(71), fe(73), fe(79)},
				eps:     fe(83),
			}
			// Ensure ValidCoins holds for deterministic coins.
			if zpt := pp.ZP.Eval(&coins.tau); zpt.IsZero() {
				t.Fatal("tau collided with QAP domain")
			}

			goS1, goS2, goKappa, goAK := pp.computeEncScalars(goPhi, coins)
			l := pp.layout()

			// Lean Enc.lean helper functions:
			lam := func(s fr.Element) []fr.Element {
				out := make([]fr.Element, N+1)
				for e := 0; e < n; e++ {
					se := pow(&s, e)
					for j := 0; j <= N; j++ {
						var prod fr.Element
						prod.Mul(&se, &goPhi[e][j])
						out[j].Add(&out[j], &prod)
					}
				}
				return out
			}
			piAt := func(k1 int) fr.Element {
				th := pow(&beta, 2*k1)
				var onePlus, out fr.Element
				onePlus.Mul(&coins.eps, &th)
				var one fr.Element
				one.SetOne()
				onePlus.Add(&onePlus, &one)
				uPow := pow(&coins.ups, 2*k1)
				out.Mul(&coins.pi, &uPow)
				out.Mul(&out, &onePlus)
				return out
			}
			legScale := func(leg int) fr.Element {
				uPow := pow(&coins.ups, par.legExp(leg))
				var out fr.Element
				out.Mul(&coins.sKind[par.legKind(leg)], &uPow)
				return out
			}
			// Interpolate QAP polynomials A_j(X), B_j(X) explicitly as in Praxis/QAP.lean.
			aPolys := make([]poly.Poly, N+1)
			bPolys := make([]poly.Poly, N+1)
			for j := 0; j <= N; j++ {
				aVals := make([]fr.Element, pp.D)
				bVals := make([]fr.Element, pp.D)
				unit := make([]bool, N+1)
				unit[j] = true
				for pIdx := 0; pIdx < pp.D; pIdx++ {
					aVals[pIdx] = pp.A[pIdx].Apply(unit)
					bVals[pIdx] = pp.B[pIdx].Apply(unit)
				}
				aPolys[j] = poly.Interpolate(pp.Points, pp.Weights, aVals)
				bPolys[j] = poly.Interpolate(pp.Points, pp.Weights, bVals)
			}

			var negU, bPrime, bPrimeU, betaM1, betaM1U, epsInv fr.Element
			negU.Neg(&coins.ups)
			bPrime.Neg(&beta)
			bPrimeU.Mul(&bPrime, &coins.ups)
			betaM1 = pow(&beta, m-1)
			betaM1U.Mul(&betaM1, &coins.ups)
			epsInv.Inverse(&coins.eps)

			LnegU := lam(negU)
			LbPrimeU := lam(bPrimeU)
			LbetaM1U := lam(betaM1U)

			leanLegMask := func(leg, j int) fr.Element {
				x := par.legExp(leg)
				ux := pow(&coins.ups, x)
				if par.legKind(leg) == kindV {
					var t1, t2, diff, out fr.Element
					t1.Mul(&coins.eta[2], &LbPrimeU[j])
					t2.Mul(&coins.eta[0], &LbetaM1U[j])
					diff.Sub(&t1, &t2)
					out.Mul(&ux, &diff)
					return out
				}
				var a1, a2, left, b1, b2, right, bux, scale2, out fr.Element
				a1.Mul(&coins.eta[0], &LnegU[j])
				a2.Mul(&coins.eta[1], &LbPrimeU[j])
				left.Add(&a1, &a2)
				left.Mul(&left, &ux)

				bux = pow(&bPrimeU, x)
				scale2.Mul(&epsInv, &bux)
				b1.Mul(&coins.eta[1], &LbetaM1U[j])
				b2.Mul(&coins.eta[2], &LnegU[j])
				right.Add(&b1, &b2)
				right.Mul(&right, &scale2)
				out.Sub(&left, &right)
				return out
			}

			// Check kappa and gtExp.
			pi0, ls0, lrhoAtTau := piAt(0), legScale(0), pp.Lrho.Eval(&coins.tau)
			var leanKappa, leanAK fr.Element
			leanKappa.Mul(&pi0, &ls0)
			leanKappa.Mul(&leanKappa, &lrhoAtTau)
			leanAK.Mul(&coins.alpha, &leanKappa)
			if !goKappa.Equal(&leanKappa) || !goAK.Equal(&leanAK) {
				t.Fatalf("kappa/gtExp mismatch: got (%s, %s), Lean (%s, %s)",
					goKappa.String(), goAK.String(), leanKappa.String(), leanAK.String())
			}

			// Check every G1Idx exponent (L1, L2, GY, QP, RP).
			for k1 := 0; k1 < par.K1; k1++ {
				pk := piAt(k1)
				for i := 0; i <= N; i++ {
					var wantL1, wantL2, t1, t2 fr.Element
					wantL1.Mul(&pk, &y[i])
					aAtTau := aPolys[i].Eval(&coins.tau)
					t1.Mul(&coins.omega12, &y[i])
					t2.Mul(&coins.omega22, &aAtTau)
					wantL2.Add(&t1, &t2)
					wantL2.Mul(&wantL2, &pk)
					if !goS1[l.f(k1, i, 0)].Equal(&wantL1) || !goS1[l.f(k1, i, 1)].Equal(&wantL2) {
						t.Fatalf("G1 L1/L2 mismatch at k1=%d i=%d", k1, i)
					}
				}
			}
			for i := 0; i <= N; i++ {
				var wantGY fr.Element
				wantGY.Mul(&coins.zeta2, &y[i])
				if !goS1[l.y(i)].Equal(&wantGY) {
					t.Fatalf("G1 GY mismatch at i=%d", i)
				}
			}
			for s := 0; s < pp.Delta; s++ {
				ts := pow(&coins.tau, s)
				var wantQP fr.Element
				wantQP.Mul(&coins.zeta, &ts)
				if !goS1[l.pquo(s)].Equal(&wantQP) {
					t.Fatalf("G1 QP mismatch at s=%d", s)
				}
			}
			for s := 0; s < pp.DeltaPrime; s++ {
				if s%pp.Nu == 0 {
					continue
				}
				ts := pow(&coins.tau, s)
				var wantRP fr.Element
				wantRP.Mul(&coins.zeta1, &ts)
				if !goS1[l.prem(s)].Equal(&wantRP) {
					t.Fatalf("G1 RP mismatch at s=%d", s)
				}
			}

			// Check every G2Idx exponent (ZeroCoordinate, R2, SC, QB, RB, GM, GB).
			for leg := 0; leg < par.legs(); leg++ {
				ls := legScale(leg)
				if !goS2[l.s(leg)].Equal(&ls) {
					t.Fatalf("G2 SC mismatch at leg=%d", leg)
				}
				for j := 0; j <= N; j++ {
					aAtTau := aPolys[j].Eval(&coins.tau)
					bAtTau := bPolys[j].Eval(&coins.tau)
					mk := leanLegMask(leg, j)
					var h1, h2, r1, r2, ratio fr.Element
					h1.Add(&r[j], &aAtTau)
					h1.Mul(&h1, &ls)
					h1.Add(&h1, &mk)
					h2.Sub(&bAtTau, &y[j])
					h2.Mul(&h2, &ls)
					ratio.Div(&coins.omega12, &coins.omega22)
					ratio.Mul(&ratio, &h2)
					r1.Sub(&h1, &ratio)
					r2.Div(&h2, &coins.omega22)
					if !goS2[l.h(leg, j, 0)].Equal(&r1) || !goS2[l.h(leg, j, 1)].Equal(&r2) {
						t.Fatalf("G2 ZeroCoordinate/R2 mismatch at leg=%d j=%d", leg, j)
					}
				}
			}
			zpAtTau := pp.ZP.Eval(&coins.tau)
			zAtTau := pp.Z.Eval(&coins.tau)
			z0AtTau := pp.Z0.Eval(&coins.tau)
			for k1 := 0; k1 < par.K1; k1++ {
				pk := piAt(k1)
				for leg := 0; leg < par.legs(); leg++ {
					ls := legScale(leg)
					var gam fr.Element
					gam.Mul(&pk, &ls)
					cel := par.cell(k1, leg)
					zCell := zAtTau
					if k1 == 0 && leg == 0 {
						zCell = zpAtTau
					}
					for j := 0; j < l.jQuo; j++ {
						tj := pow(&coins.tau, pp.Delta*j)
						var wantQB fr.Element
						wantQB.Mul(&gam, &zCell)
						wantQB.Mul(&wantQB, &tj)
						wantQB.Div(&wantQB, &coins.zeta)
						if !goS2[l.bquo(cel, j)].Equal(&wantQB) {
							t.Fatalf("G2 QB mismatch at cell=%d j=%d", cel, j)
						}
					}
					for j := 0; j < l.jRem; j++ {
						tj := pow(&coins.tau, pp.DeltaPrime*j)
						var wantRB fr.Element
						wantRB.Mul(&gam, &z0AtTau)
						wantRB.Mul(&wantRB, &tj)
						wantRB.Div(&wantRB, &coins.zeta1)
						if !goS2[l.brem(cel, j)].Equal(&wantRB) {
							t.Fatalf("G2 RB mismatch at cell=%d j=%d", cel, j)
						}
					}
				}
			}
			var kummerAtU fr.Element
			uN := pow(&coins.ups, n)
			kummerAtU.Sub(&uN, &c0)
			for s := 0; s < 3; s++ {
				for e := 0; e < n-1; e++ {
					ue := pow(&coins.ups, e)
					var wantGM fr.Element
					wantGM.Mul(&coins.pi, &coins.eta[s])
					wantGM.Mul(&wantGM, &kummerAtU)
					wantGM.Mul(&wantGM, &ue)
					wantGM.Div(&wantGM, &coins.zeta2)
					if !goS2[l.tie(s, e)].Equal(&wantGM) {
						t.Fatalf("G2 GM mismatch at s=%d e=%d", s, e)
					}
				}
			}
			var c1eps, c2eps, c2div, c3eps, c3div fr.Element
			c1eps.Mul(&coins.eta[0], &coins.eps)
			c2eps.Mul(&coins.eta[1], &coins.eps)
			c2div.Div(&coins.eta[1], &coins.eps)
			c3eps.Mul(&coins.eta[2], &coins.eps)
			c3div.Div(&coins.eta[2], &coins.eps)
			leanCrossVals := [crossFamilies]fr.Element{c1eps, c2eps, c2div, c3eps, c3div}
			for fam := 0; fam < crossFamilies; fam++ {
				for e := 0; e < 2*n-1; e++ {
					ue := pow(&coins.ups, e)
					var wantGB fr.Element
					wantGB.Mul(&coins.pi, &leanCrossVals[fam])
					wantGB.Mul(&wantGB, &ue)
					wantGB.Div(&wantGB, &coins.zeta2)
					if !goS2[l.cross(fam, e)].Equal(&wantGB) {
						t.Fatalf("G2 GB mismatch at fam=%d e=%d", fam, e)
					}
				}
			}

			// --- 4. Praxis/Dec.lean: evalComb, psi, findT, decRef in expGroups (Additive F_q) ---
			hKey, hOth, rem, exact := pp.quotients(wBool)
			if !exact {
				t.Fatal("expected exact QAP quotients on valid witness")
			}
			var negBeta fr.Element
			negBeta.Neg(&beta)
			u1, v1, u2 := make(poly.Poly, n), make(poly.Poly, n), make(poly.Poly, n)
			for k := 0; k < n; k++ {
				k1 := (k / 2) % par.K1
				a := pow(&beta, 2*k1)
				b := pow(&negBeta, k-2*k1)
				u1[k].Mul(&wt.U[k], &a)
				v1[k].Mul(&wt.V[k], &a)
				u2[k].Mul(&wt.U[k], &b)
			}
			uRot := wt.U.Substitute(&negBeta)
			modulus := pp.fld.modulus()
			tieQ := func(a, b poly.Poly) poly.Poly {
				q, rRem := poly.DivMod(poly.Sub(a, b), modulus)
				if len(rRem) != 0 {
					t.Fatalf("non-exact tie division in Equation (6)")
				}
				return q
			}
			x0 := [3]poly.Poly{
				tieQ(poly.Mul(wt.U, wt.zCirc), poly.Mul(wt.V, wt.zMinus)),
				tieQ(poly.Mul(wt.U, wt.zPlus), poly.Mul(uRot, wt.zMinus)),
				tieQ(poly.Mul(wt.V, wt.zPlus), poly.Mul(uRot, wt.zCirc)),
			}
			xc := [crossFamilies]poly.Poly{
				poly.Sub(poly.Mul(u1, wt.zCirc), poly.Mul(v1, wt.zMinus)),
				poly.Mul(u1, wt.zPlus),
				poly.Sub(nil, poly.Mul(u2, wt.zMinus)),
				poly.Mul(v1, wt.zPlus),
				poly.Sub(nil, poly.Mul(u2, wt.zCirc)),
			}

			// Verify Dec.lean's cell-summed crossPoly against Go's polynomial xc!
			leanShiftLam := func(wCell, a fr.Element, cellExp, e int) fr.Element {
				if cellExp <= e && e-cellExp < n {
					ae := pow(&a, e-cellExp)
					var out fr.Element
					out.Mul(&wCell, &ae)
					out.Mul(&out, &zOf[e-cellExp])
					return out
				}
				return fr.Element{}
			}
			var minusOne fr.Element
			minusOne.SetInt64(-1)
			for e := 0; e < 2*n-1; e++ {
				var lC1, lC2, lC2d, lC3, lC3d fr.Element
				for k1 := 0; k1 < par.K1; k1++ {
					th := pow(&beta, 2*k1)
					for leg := 0; leg < par.legs(); leg++ {
						wCell := par.xi(&wt, k1, leg)
						cExp := 2*k1 + par.legExp(leg)
						bLeg := pow(&negBeta, par.legExp(leg))
						var tmp fr.Element
						if par.legKind(leg) != kindV {
							s1 := leanShiftLam(wCell, minusOne, cExp, e)
							tmp.Mul(&th, &s1)
							lC1.Add(&lC1, &tmp)

							s2 := leanShiftLam(wCell, negBeta, cExp, e)
							tmp.Mul(&th, &s2)
							lC2.Add(&lC2, &tmp)

							s2d := leanShiftLam(wCell, betaM1, cExp, e)
							tmp.Mul(&bLeg, &s2d)
							lC2d.Sub(&lC2d, &tmp)

							s3d := leanShiftLam(wCell, minusOne, cExp, e)
							tmp.Mul(&bLeg, &s3d)
							lC3d.Sub(&lC3d, &tmp)
						} else {
							s1v := leanShiftLam(wCell, betaM1, cExp, e)
							tmp.Mul(&th, &s1v)
							lC1.Sub(&lC1, &tmp)

							s3 := leanShiftLam(wCell, negBeta, cExp, e)
							tmp.Mul(&th, &s3)
							lC3.Add(&lC3, &tmp)
						}
					}
				}
				leanXC := [crossFamilies]fr.Element{lC1, lC2, lC2d, lC3, lC3d}
				for fam := 0; fam < crossFamilies; fam++ {
					got := xc[fam].Coeff(e)
					if !got.Equal(&leanXC[fam]) {
						t.Fatalf("Dec.lean crossPoly mismatch at fam=%d e=%d: got %s, Lean %s",
							fam, e, got.String(), leanXC[fam].String())
					}
				}
			}

			// Evaluate Dec.lean's evalComb and psi in expGroups (where pair(a, b) = a * b in F_q).
			evalCombScalar := func(sector fr.Element) (lambda, psi fr.Element) {
				var p fr.Element
				for k1 := 0; k1 < par.K1; k1++ {
					for leg := 0; leg < par.legs(); leg++ {
						wCell := par.xi(&wt, k1, leg)
						for i := 0; i <= N; i++ {
							if !wBool[i] {
								continue
							}
							// psi term: wCell * L1(k1, i) * SC(sector, leg)
							p.Mul(&goS1[l.f(k1, i, 0)], &goS2[l.s(leg)])
							p.Mul(&p, &sector)
							p.Mul(&p, &wCell)
							psi.Add(&psi, &p)

							for j := 0; j <= N; j++ {
								if !wBool[j] {
									continue
								}
								var pair0, pair1, sumP fr.Element
								pair0.Mul(&goS1[l.f(k1, i, 0)], &goS2[l.h(leg, j, 0)])
								pair1.Mul(&goS1[l.f(k1, i, 1)], &goS2[l.h(leg, j, 1)])
								sumP.Add(&pair0, &pair1)
								sumP.Mul(&sumP, &sector)
								sumP.Mul(&sumP, &wCell)
								lambda.Add(&lambda, &sumP)
							}
						}
						cel := par.cell(k1, leg)
						hPoly := hOth
						if cel == 0 {
							hPoly = hKey
						}
						for a := 0; a < pp.Delta; a++ {
							for j := 0; j < l.jQuo; j++ {
								hc := hPoly.Coeff(a + pp.Delta*j)
								p.Mul(&goS1[l.pquo(a)], &goS2[l.bquo(cel, j)])
								p.Mul(&p, &sector)
								p.Mul(&p, &hc)
								p.Mul(&p, &wCell)
								lambda.Sub(&lambda, &p)
							}
						}
						for a := 0; a < pp.DeltaPrime; a++ {
							if a%pp.Nu == 0 {
								continue
							}
							for j := 0; j < l.jRem; j++ {
								rc := rem.Coeff(a + pp.DeltaPrime*j)
								p.Mul(&goS1[l.prem(a)], &goS2[l.brem(cel, j)])
								p.Mul(&p, &sector)
								p.Mul(&p, &rc)
								p.Mul(&p, &wCell)
								lambda.Sub(&lambda, &p)
							}
						}
					}
				}
				var sumGY fr.Element
				for i := 0; i <= N; i++ {
					if wBool[i] {
						sumGY.Add(&sumGY, &goS1[l.y(i)])
					}
				}
				for s := 0; s < 3; s++ {
					for e := 0; e < n-1; e++ {
						qc := x0[s].Coeff(e)
						p.Mul(&sumGY, &goS2[l.tie(s, e)])
						p.Mul(&p, &sector)
						p.Mul(&p, &qc)
						lambda.Sub(&lambda, &p)
					}
				}
				for fam := 0; fam < crossFamilies; fam++ {
					for e := 0; e < 2*n-1; e++ {
						xcc := xc[fam].Coeff(e)
						p.Mul(&sumGY, &goS2[l.cross(fam, e)])
						p.Mul(&p, &sector)
						p.Mul(&p, &xcc)
						lambda.Sub(&lambda, &p)
					}
				}
				return lambda, psi
			}

			var one fr.Element
			one.SetOne()
			lam0, psi0 := evalCombScalar(one)
			lam1, psi1 := evalCombScalar(coins.alpha)
			wk := par.xi(&wt, 0, 0)
			cx := centerBig(N, par.G, wBool)
			var cxFE fr.Element
			cxFE.SetBigInt(cx)

			// Dec.lean line 442: H' = Lambda1 - wk * gT - cx * Psi1
			var hPrime, t1, t2 fr.Element
			t1.Mul(&wk, &goAK)
			t2.Mul(&cxFE, &psi1)
			hPrime.Sub(&lam1, &t1)
			hPrime.Sub(&hPrime, &t2)

			// True secret sum rw = sum_{j: w[j]} r_j
			var rwFE, wantOffset fr.Element
			for j := 0; j <= N; j++ {
				if wBool[j] {
					rwFE.Add(&rwFE, &r[j])
				}
			}
			wantOffset.Sub(&rwFE, &cxFE)
			var checkHPrime fr.Element
			checkHPrime.Mul(&wantOffset, &psi1)
			if !hPrime.Equal(&checkHPrime) {
				t.Fatalf("Dec.lean H' != (r(w) - c(w)) * Psi1: got %s, want %s",
					hPrime.String(), checkHPrime.String())
			}

			// Dec.lean line 448: K = wk^-1 * (Lambda0 - (cx + t) * Psi0) == kappa!
			var recoveredKappa, rwPsi0 fr.Element
			rwPsi0.Mul(&rwFE, &psi0)
			recoveredKappa.Sub(&lam0, &rwPsi0)
			recoveredKappa.Div(&recoveredKappa, &wk)
			if !recoveredKappa.Equal(&goKappa) {
				t.Fatalf("Dec.lean recovered K = %s, want kappa = %s",
					recoveredKappa.String(), goKappa.String())
			}
		})
	}
}

// TestSignClassKDFInvarianceAndRoundTrip verifies Praxis/Keys.lean's Section 6.4
// sign-class key derivation ({V, V^-1} via V.C0) is invariant under unitary
// inversion/conjugation in GT and round-trips cleanly through Enc and Dec.
func TestSignClassKDFInvarianceAndRoundTrip(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()
	gt, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		t.Fatal(err)
	}
	var v, vInv, vConj bn254.GT
	v.Exp(gt, big.NewInt(987654321))
	vInv.Inverse(&v)
	vConj.Conjugate(&v)
	if !vInv.Equal(&vConj) {
		t.Fatal("GT element failed unitary identity V^-1 == Conjugate(V)")
	}
	padPos := keyPadFor(&v, 64, true)
	padNeg := keyPadFor(&vInv, 64, true)
	if !bytes.Equal(padPos, padNeg) {
		t.Fatal("SignClassKDF pad differed between V and V^-1")
	}
	if bytes.Equal(padPos, keyPadFor(&v, 64, false)) {
		t.Fatal("SignClassKDF pad collided with full-GT pad")
	}

	par := Advanced
	par.SignClassKDF = true
	sys, err := bqs.Factoring(big.NewInt(21), 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	pp, err := Setup(par, sys.PadConstraints(par.JRem()))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("sign-class-kdf-praxis-lean-roundtrip")
	ct, err := Enc(pp, msg)
	if err != nil {
		t.Fatal(err)
	}
	w := bqs.FactoringWitness(big.NewInt(3), big.NewInt(7), 4, 4)
	got, err := Dec(pp, ct, w)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("SignClassKDF round-trip failed: got %q, err %v", got, err)
	}
}
