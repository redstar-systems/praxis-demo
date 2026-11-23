package praxis

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"praxis-demo/poly"
)

var (
	// ErrNotWitness is returned when the assignment does not solve the system.
	ErrNotWitness = errors.New("praxis: the assignment is not a solution of the system")
	// ErrFailed is returned when decryption finds no key. For a real
	// solution this happens with probability about 2/q.
	ErrFailed = errors.New("praxis: decryption failed")
)

// Dec decrypts with a solution w of the system (w[0] true, then the N
// unknowns).
func Dec(pp *Public, ct *Ciphertext, w []bool) ([]byte, error) {
	if !pp.S.IsWitness(w) {
		return nil, ErrNotWitness
	}
	return dec(pp, ct, w)
}

// DecUnchecked runs decryption's algebra on any assignment, without first
// checking that it solves the system. It exists to show that a wrong
// assignment gets nothing: the divisions are no longer exact, their
// remainders are dropped, and what comes out is ErrFailed or noise.
func DecUnchecked(pp *Public, ct *Ciphertext, w []bool) ([]byte, error) {
	if len(w) != pp.S.N+1 || !w[0] {
		return nil, ErrNotWitness
	}
	return dec(pp, ct, w)
}

func msm1(points []bn254.G1Affine, scalars []fr.Element) bn254.G1Affine {
	var out bn254.G1Affine
	if len(points) == 0 {
		return out
	}
	if _, err := out.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
		panic(err)
	}
	return out
}

func msm2(points []bn254.G2Affine, scalars []fr.Element) bn254.G2Affine {
	var out bn254.G2Affine
	if len(points) == 0 {
		return out
	}
	if _, err := out.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
		panic(err)
	}
	return out
}

// pad returns p's first n coefficients, zero-filled.
func pad(p poly.Poly, n int) []fr.Element {
	out := make([]fr.Element, n)
	copy(out, p)
	return out
}

func dec(pp *Public, ct *Ciphertext, w []bool) ([]byte, error) {
	if err := ct.check(pp); err != nil {
		return nil, err
	}
	par, N, f := pp.Par, pp.S.N, pp.fld
	n := par.NForms()
	l := pp.layout()

	// Lines 1 and 2: the forms and the weights at w.
	phi := par.forms(ct.Seed, N)
	wt := par.weightsOf(f, phi, w)
	xiKey := par.xi(&wt, 0, 0)
	if xiKey.IsZero() {
		return nil, ErrFailed
	}
	xi := make([]fr.Element, par.Cells())
	for k1 := 0; k1 < par.K1; k1++ {
		for leg := 0; leg < par.legs(); leg++ {
			xi[par.cell(k1, leg)] = par.xi(&wt, k1, leg)
		}
	}

	// Line 3: the quotients and the remainder.
	hKey, hOth, rem, _ := pp.quotients(w)

	// Line 4: the cancellation polynomials (Equation (6)). U1 and V1 scale
	// each cell's term by omega^(2*k1); U2 scales it by (-omega)^kleg; Urot
	// is U with T replaced by -omega*T.
	var negOmega fr.Element
	negOmega.Neg(&f.omega)
	u1, v1, u2 := make(poly.Poly, n), make(poly.Poly, n), make(poly.Poly, n)
	for k := 0; k < n; k++ {
		k1 := (k / 2) % par.K1
		a := pow(&f.omega, 2*k1)
		b := pow(&negOmega, k-2*k1)
		u1[k].Mul(&wt.U[k], &a)
		v1[k].Mul(&wt.V[k], &a)
		u2[k].Mul(&wt.U[k], &b)
	}
	uRot := wt.U.Substitute(&negOmega)
	modulus := f.modulus()
	tieQuot := func(a, b poly.Poly) poly.Poly {
		q, _ := poly.DivMod(poly.Sub(a, b), modulus)
		return q
	}
	neg := func(p poly.Poly) poly.Poly { return poly.Sub(nil, p) }
	x0 := [3]poly.Poly{
		tieQuot(poly.Mul(wt.U, wt.zCirc), poly.Mul(wt.V, wt.zMinus)),
		tieQuot(poly.Mul(wt.U, wt.zPlus), poly.Mul(uRot, wt.zMinus)),
		tieQuot(poly.Mul(wt.V, wt.zPlus), poly.Mul(uRot, wt.zCirc)),
	}
	var xc [crossFamilies]poly.Poly
	xc[cross1Plus] = poly.Sub(poly.Mul(u1, wt.zCirc), poly.Mul(v1, wt.zMinus))
	xc[cross2Plus] = poly.Mul(u1, wt.zPlus)
	xc[cross2Minus] = neg(poly.Mul(u2, wt.zMinus))
	xc[cross3Plus] = poly.Mul(v1, wt.zPlus)
	xc[cross3Minus] = neg(poly.Mul(u2, wt.zCirc))

	// Line 5: sums of left factors over the ones of w, then over each
	// column of the grid with the cells' weights.
	fw := make([][2]bn254.G1Jac, par.K1)
	var yw bn254.G1Jac
	for i, on := range w {
		if !on {
			continue
		}
		for k1 := range fw {
			fw[k1][0].AddMixed(&ct.G1[l.f(k1, i, 0)])
			fw[k1][1].AddMixed(&ct.G1[l.f(k1, i, 1)])
		}
		yw.AddMixed(&ct.G1[l.y(i)])
	}
	fwAff := [2][]bn254.G1Affine{make([]bn254.G1Affine, par.K1), make([]bn254.G1Affine, par.K1)}
	for k1 := range fw {
		fwAff[0][k1].FromJacobian(&fw[k1][0])
		fwAff[1][k1].FromJacobian(&fw[k1][1])
	}
	fLeg := make([][2]bn254.G1Affine, par.legs())
	col := make([]fr.Element, par.K1)
	for leg := range fLeg {
		for k1 := range col {
			col[k1] = xi[par.cell(k1, leg)]
		}
		fLeg[leg][0] = msm1(fwAff[0], col)
		fLeg[leg][1] = msm1(fwAff[1], col)
	}

	// Line 6: the quotients and the remainder in the exponent.
	pquo := ct.G1[l.pquo(0):l.pquo(pp.D)]
	pKey := msm1(pquo, pad(hKey, pp.D))
	pOth := msm1(pquo, pad(hOth, pp.D))
	var remPts []bn254.G1Affine
	var remSc []fr.Element
	for k := 0; k < pp.cosetLen(); k++ {
		if k%pp.Nu != 0 {
			remPts = append(remPts, ct.G1[l.prem(k)])
			remSc = append(remSc, rem.Coeff(k))
		}
	}
	pRem := msm1(remPts, remSc)
	var ywAff bn254.G1Affine
	ywAff.FromJacobian(&yw)

	// Comb: one product of pairings for Lambda and one for Psi.
	xiOth := make([]fr.Element, len(xi))
	copy(xiOth, xi)
	xiOth[0].SetZero()
	xiKeyOnly := []fr.Element{xiKey}
	comb := func(g2 []bn254.G2Affine) (lambda, psi bn254.GT, err error) {
		var ps []bn254.G1Affine
		var qs []bn254.G2Affine
		var psiP []bn254.G1Affine
		var psiQ []bn254.G2Affine
		for leg := 0; leg < par.legs(); leg++ {
			var hw [2]bn254.G2Jac
			for j, on := range w {
				if on {
					hw[0].AddMixed(&g2[l.h(leg, j, 0)])
					hw[1].AddMixed(&g2[l.h(leg, j, 1)])
				}
			}
			for coord := 0; coord < 2; coord++ {
				var q bn254.G2Affine
				q.FromJacobian(&hw[coord])
				ps = append(ps, fLeg[leg][coord])
				qs = append(qs, q)
			}
			psiP = append(psiP, fLeg[leg][0])
			psiQ = append(psiQ, g2[l.s(leg)])
		}
		sub := func(p bn254.G1Affine, q bn254.G2Affine) {
			p.Neg(&p)
			ps = append(ps, p)
			qs = append(qs, q)
		}
		cells := par.Cells()
		sub(pKey, msm2(g2[l.bquo(0):l.bquo(1)], xiKeyOnly))
		sub(pOth, msm2(g2[l.bquo(0):l.bquo(cells)], xiOth))
		sub(pRem, msm2(g2[l.brem(0):l.brem(cells)], xi))

		var bPts []bn254.G2Affine
		var bSc []fr.Element
		for a := 0; a < 3; a++ {
			bPts = append(bPts, g2[l.tie(a, 0):l.tie(a, n-1)]...)
			bSc = append(bSc, pad(x0[a], n-1)...)
		}
		for fam := 0; fam < crossFamilies; fam++ {
			bPts = append(bPts, g2[l.cross(fam, 0):l.cross(fam, 2*n-1)]...)
			bSc = append(bSc, pad(xc[fam], 2*n-1)...)
		}
		sub(ywAff, msm2(bPts, bSc))

		if lambda, err = bn254.Pair(ps, qs); err != nil {
			return
		}
		psi, err = bn254.Pair(psiP, psiQ)
		return
	}
	lambda, psi, err := comb(ct.G2)
	if err != nil {
		return nil, err
	}
	lambdaA, psiA, err := comb(ct.G2a)
	if err != nil {
		return nil, err
	}

	// Lines 8 to 10: remove the key and the center from the alpha side, and
	// search for what is left of the secret sum.
	cw := center(N, par.G, w)
	q := fr.Modulus()
	gtExp := func(x *bn254.GT, k *big.Int) bn254.GT {
		var out bn254.GT
		out.Exp(*x, new(big.Int).Mod(k, q))
		return out
	}
	xiKeyInt := xiKey.BigInt(new(big.Int))
	t1 := gtExp(&ct.Ka, new(big.Int).Neg(xiKeyInt))
	t2 := gtExp(&psiA, big.NewInt(-cw))
	var target bn254.GT
	target.Mul(&lambdaA, &t1)
	target.Mul(&target, &t2)
	bound := (int64(N) + 1) * (par.G + 1)
	t, ok := search(&psiA, &target, bound)
	if !ok {
		return nil, ErrFailed
	}

	// Line 11: K = (Lambda - (cw + t) * Psi) / xiKey.
	t3 := gtExp(&psi, big.NewInt(-(cw + t)))
	var key bn254.GT
	key.Mul(&lambda, &t3)
	var xiInv fr.Element
	xiInv.Inverse(&xiKey)
	key = gtExp(&key, xiInv.BigInt(new(big.Int)))
	return xor(ct.Msg, keyPad(&key, len(ct.Msg))), nil
}

// center is the middle of the range the secret sum r(w) can take under the
// centered sampler (Section 5.2):
// floor(ceil(N(g+1)/2) + (g+3)/2 * (1 + wt(w) - N/2)).
func center(N int, g int64, w []bool) int64 {
	var wt int64
	for _, on := range w[1:] {
		if on {
			wt++
		}
	}
	a := (int64(N)*(g+1) + 1) / 2
	num := (g + 3) * (2 + 2*wt - int64(N)) // four times the second term
	fl := num / 4
	if num%4 != 0 && num < 0 {
		fl--
	}
	return a + fl
}

// search returns the integer t with |t| <= bound and base^t = target, by
// baby steps and giant steps over the whole range. The paper searches
// outward from zero, which is faster on average; at the demo's range the
// difference does not matter.
func search(base, target *bn254.GT, bound int64) (int64, bool) {
	if base.IsOne() {
		return 0, target.IsOne()
	}
	// Look for u = t + bound in [0, 2*bound].
	m := int64(1)
	for m*m < 2*bound+1 {
		m++
	}
	table := make(map[[bn254.SizeOfGT]byte]int64, m)
	var cur bn254.GT
	cur.SetOne()
	for b := int64(0); b < m; b++ {
		table[cur.Bytes()] = b
		cur.Mul(&cur, base)
	}
	var giant, shifted bn254.GT
	giant.Inverse(&cur) // base^-m
	shifted.Exp(*base, big.NewInt(bound))
	shifted.Mul(&shifted, target)
	for j := int64(0); j <= m; j++ {
		if b, ok := table[shifted.Bytes()]; ok {
			if u := j*m + b; u <= 2*bound {
				return u - bound, true
			}
		}
		shifted.Mul(&shifted, &giant)
	}
	return 0, false
}
