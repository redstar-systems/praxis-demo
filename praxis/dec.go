package praxis

import (
	"errors"
	"math/big"
	"time"

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
	msg, _, err := DecDetailed(pp, ct, w)
	return msg, err
}

// DecDetailed decrypts with a solution w and returns telemetry alongside the message.
func DecDetailed(pp *Public, ct *Ciphertext, w []bool) ([]byte, DecReport, error) {
	if pp == nil || !pp.S.IsWitness(w) {
		return nil, DecReport{}, ErrNotWitness
	}
	return dec(pp, ct, w)
}

// DecUnchecked runs decryption's algebra on any assignment, without first
// checking that it solves the system. It exists to show that a wrong
// assignment gets nothing: the divisions are no longer exact, their
// remainders are dropped, and what comes out is ErrFailed or noise.
func DecUnchecked(pp *Public, ct *Ciphertext, w []bool) ([]byte, error) {
	msg, _, err := DecUncheckedDetailed(pp, ct, w)
	return msg, err
}

// DecUncheckedDetailed runs DecUnchecked and returns telemetry alongside any output.
func DecUncheckedDetailed(pp *Public, ct *Ciphertext, w []bool) ([]byte, DecReport, error) {
	if pp == nil || len(w) != pp.S.N+1 || !w[0] {
		return nil, DecReport{}, ErrNotWitness
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

// chunkCoeffs returns p's coefficients from X^start to X^(start+length-1).
func chunkCoeffs(p poly.Poly, start, length int) []fr.Element {
	out := make([]fr.Element, length)
	if start < len(p) {
		copy(out, p[start:])
	}
	return out
}

func dec(pp *Public, ct *Ciphertext, w []bool) ([]byte, DecReport, error) {
	var rep DecReport
	totalStart := time.Now()
	if err := ct.check(pp); err != nil {
		return nil, rep, err
	}
	par, N, f := pp.Par, pp.S.N, pp.fld
	n := par.NForms()
	l := pp.layout()
	rep.Pairings = 18*par.K2 + 4*l.jQuo + 2*l.jRem + 2

	// Lines 1 and 2: the forms and the weights at w.
	t0 := time.Now()
	phi := par.forms(ct.Seed, N)
	wt := par.weightsOf(f, phi, w)
	xiKey := par.xi(&wt, 0, 0)
	if xiKey.IsZero() {
		rep.TotalDur = time.Since(totalStart)
		return nil, rep, ErrFailed
	}
	xi := make([]fr.Element, par.Cells())
	for k1 := 0; k1 < par.K1; k1++ {
		for leg := 0; leg < par.legs(); leg++ {
			xi[par.cell(k1, leg)] = par.xi(&wt, k1, leg)
		}
	}
	rep.FormsDur = time.Since(t0)

	// Line 3: the quotients and the remainder.
	tQAP := time.Now()
	hKey, hOth, rem, exact := pp.quotients(w)
	rep.ExactQAP = exact

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
	mulPoly := poly.Mul
	divPoly := poly.DivMod
	if par.Fast {
		mulPoly = poly.MulFFT
		divPoly = poly.DivModFFT
	}
	tieQuot := func(a, b poly.Poly) poly.Poly {
		q, _ := divPoly(poly.Sub(a, b), modulus)
		return q
	}
	neg := func(p poly.Poly) poly.Poly { return poly.Sub(nil, p) }
	x0 := [3]poly.Poly{
		tieQuot(mulPoly(wt.U, wt.zCirc), mulPoly(wt.V, wt.zMinus)),
		tieQuot(mulPoly(wt.U, wt.zPlus), mulPoly(uRot, wt.zMinus)),
		tieQuot(mulPoly(wt.V, wt.zPlus), mulPoly(uRot, wt.zCirc)),
	}
	var xc [crossFamilies]poly.Poly
	xc[cross1Plus] = poly.Sub(mulPoly(u1, wt.zCirc), mulPoly(v1, wt.zMinus))
	xc[cross2Plus] = mulPoly(u1, wt.zPlus)
	xc[cross2Minus] = neg(mulPoly(u2, wt.zMinus))
	xc[cross3Plus] = mulPoly(v1, wt.zPlus)
	xc[cross3Minus] = neg(mulPoly(u2, wt.zCirc))
	rep.QAPDur = time.Since(tQAP)

	// Line 5: sums of left factors over the ones of w, then over each
	// column of the grid with the cells' weights.
	tPair := time.Now()
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

	// Line 6: the quotients and the remainder in the exponent (across J and J' chunks).
	pquo := ct.G1[l.pquo(0) : l.pquo(0)+pp.Delta]
	pKey := make([]bn254.G1Affine, l.jQuo)
	pOth := make([]bn254.G1Affine, l.jQuo)
	for j := 0; j < l.jQuo; j++ {
		pKey[j] = msm1(pquo, chunkCoeffs(hKey, j*pp.Delta, pp.Delta))
		pOth[j] = msm1(pquo, chunkCoeffs(hOth, j*pp.Delta, pp.Delta))
	}
	remPts := ct.G1[l.premBase() : l.premBase()+l.nRem]
	pRem := make([]bn254.G1Affine, l.jRem)
	remSc := make([]fr.Element, 0, l.nRem)
	for j := 0; j < l.jRem; j++ {
		remSc = remSc[:0]
		baseExp := j * pp.DeltaPrime
		for k := 0; k < pp.DeltaPrime; k++ {
			if k%pp.Nu != 0 {
				remSc = append(remSc, rem.Coeff(baseExp+k))
			}
		}
		pRem[j] = msm1(remPts, remSc)
	}
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
		for j := 0; j < l.jQuo; j++ {
			sub(pKey[j], msm2(g2[l.bquo(0, j):l.bquo(1, j)], xiKeyOnly))
			sub(pOth[j], msm2(g2[l.bquo(0, j):l.bquo(cells, j)], xiOth))
		}
		for j := 0; j < l.jRem; j++ {
			sub(pRem[j], msm2(g2[l.brem(0, j):l.brem(cells, j)], xi))
		}

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
		return nil, rep, err
	}
	lambdaA, psiA, err := comb(ct.G2a)
	if err != nil {
		return nil, rep, err
	}
	rep.PairingsDur = time.Since(tPair)

	// Lines 8 to 10: remove the key and the center from the alpha side, and
	// search for what is left of the secret sum.
	tSearch := time.Now()
	cw := centerBig(N, par.G, w)
	q := fr.Modulus()
	gtExp := func(x *bn254.GT, k *big.Int) bn254.GT {
		var out bn254.GT
		out.Exp(*x, new(big.Int).Mod(k, q))
		return out
	}
	xiKeyInt := xiKey.BigInt(new(big.Int))
	t1 := gtExp(&ct.Ka, new(big.Int).Neg(xiKeyInt))
	t2 := gtExp(&psiA, new(big.Int).Neg(cw))
	var target bn254.GT
	target.Mul(&lambdaA, &t1)
	target.Mul(&target, &t2)
	bound := new(big.Int).Mul(big.NewInt(int64(N)+1), big.NewInt(par.G+1))

	var t *big.Int
	var ok bool
	var sStats SearchStats
	if par.Fast {
		t, ok, sStats = searchOutwardSignFP64(&psiA, &target, bound, N, par.G)
	} else {
		t, ok, sStats = searchBigWithStats(&psiA, &target, bound)
	}
	sStats.Center = new(big.Int).Set(cw)
	rep.Search = sStats
	rep.SearchDur = time.Since(tSearch)
	if !ok {
		rep.TotalDur = time.Since(totalStart)
		return nil, rep, ErrFailed
	}

	// Line 11: K = (Lambda - (cw + t) * Psi) / xiKey.
	rw := new(big.Int).Add(cw, t)
	rep.Search.SecretSum = new(big.Int).Set(rw)
	t3 := gtExp(&psi, new(big.Int).Neg(rw))
	var key bn254.GT
	key.Mul(&lambda, &t3)
	var xiInv fr.Element
	xiInv.Inverse(&xiKey)
	key = gtExp(&key, xiInv.BigInt(new(big.Int)))
	rep.TotalDur = time.Since(totalStart)
	return xor(ct.Msg, keyPad(&key, len(ct.Msg))), rep, nil
}

// centerBig is the middle of the range the secret sum r(w) can take under the
// centered sampler (Section 5.2):
// floor(ceil(N(g+1)/2) + (g+3)/2 * (1 + wt(w) - N/2)).
func centerBig(N int, g int64, w []bool) *big.Int {
	var wt int64
	for _, on := range w[1:] {
		if on {
			wt++
		}
	}
	a := new(big.Int).Mul(big.NewInt(int64(N)), big.NewInt(g+1))
	a.Add(a, big.NewInt(1))
	a.Rsh(a, 1)

	// Four times the second term: (g + 3) * (2 + 2*wt - N).
	num := new(big.Int).Mul(big.NewInt(g+3), big.NewInt(2+2*wt-int64(N)))
	fl := new(big.Int).Div(num, big.NewInt(4)) // Euclidean division: floor(num / 4)
	return a.Add(a, fl)
}

func center(N int, g int64, w []bool) int64 {
	return centerBig(N, g, w).Int64()
}

// search returns the integer t of least absolute value with |t| <= bound and
// base^t = target.
func search(base, target *bn254.GT, bound int64) (int64, bool) {
	t, ok := searchBig(base, target, big.NewInt(bound))
	if !ok {
		return 0, false
	}
	return t.Int64(), true
}

// searchBig searches growing intervals |t| <= r up to bound by baby steps and
// giant steps (Proposition 5.7(d)), returning the solution of least absolute
// value in [-bound, bound].
func searchBig(base, target *bn254.GT, bound *big.Int) (*big.Int, bool) {
	t, ok, _ := searchBigWithStats(base, target, bound)
	return t, ok
}

func searchBigWithStats(base, target *bn254.GT, bound *big.Int) (*big.Int, bool, SearchStats) {
	stats := SearchStats{
		Algorithm: "growing-bsgs",
		Bound:     new(big.Int).Set(bound),
	}
	if bound.Sign() < 0 {
		return nil, false, stats
	}
	if target.IsOne() {
		stats.Offset = new(big.Int)
		stats.Rounds = 1
		return new(big.Int), true, stats
	}
	if base.IsOne() {
		return nil, false, stats
	}
	r := big.NewInt(1024)
	if r.Cmp(bound) > 0 {
		r.Set(bound)
	}
	for {
		stats.Rounds++
		t, bSteps, gSteps, ok := bsgsInterval(base, target, r)
		stats.BabySteps += bSteps
		stats.GiantSteps += gSteps
		if bSteps*int64(bn254.SizeOfGT+8) > stats.TableBytes {
			stats.TableBytes = bSteps * int64(bn254.SizeOfGT+8)
		}
		if ok {
			stats.Offset = t
			return t, true, stats
		}
		if r.Cmp(bound) >= 0 {
			return nil, false, stats
		}
		r.Lsh(r, 4) // multiply radius by 16 (step count by 4)
		if r.Cmp(bound) > 0 {
			r.Set(bound)
		}
	}
}

func bsgsInterval(base, target *bn254.GT, r *big.Int) (*big.Int, int64, int64, bool) {
	// Look for u = t + r in [0, 2*r].
	twoR := new(big.Int).Lsh(r, 1)
	span := new(big.Int).Add(twoR, big.NewInt(1)) // 2*r + 1
	mBig := new(big.Int).Sqrt(span)
	if new(big.Int).Mul(mBig, mBig).Cmp(span) < 0 {
		mBig.Add(mBig, big.NewInt(1))
	}
	m := mBig.Int64()
	table := make(map[[bn254.SizeOfGT]byte]int64, m)
	var cur bn254.GT
	cur.SetOne()
	for b := int64(0); b < m; b++ {
		key := cur.Bytes()
		if _, exists := table[key]; !exists {
			table[key] = b
		}
		cur.Mul(&cur, base)
	}
	var giant, shifted bn254.GT
	giant.Inverse(&cur) // base^-m
	shifted.Exp(*base, r)
	shifted.Mul(&shifted, target)

	var best, bestAbs *big.Int
	var u, cand, candAbs big.Int
	for j := int64(0); j <= m; j++ {
		if b, ok := table[shifted.Bytes()]; ok {
			u.Mul(big.NewInt(j), mBig)
			u.Add(&u, big.NewInt(b))
			if u.Cmp(twoR) <= 0 {
				cand.Sub(&u, r)
				candAbs.Abs(&cand)
				if best == nil || candAbs.Cmp(bestAbs) < 0 {
					best = new(big.Int).Set(&cand)
					bestAbs = new(big.Int).Set(&candAbs)
				}
			}
		}
		shifted.Mul(&shifted, &giant)
	}
	if best != nil {
		return best, m, m + 1, true
	}
	return nil, m, m + 1, false
}
