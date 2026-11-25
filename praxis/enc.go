package praxis

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Ciphertext is the output of Enc (Figure 9). G1 and G2 are flat lists whose
// order layout describes; G2a is G2 with every element multiplied by the
// hidden scalar alpha, which the search in decryption works on.
type Ciphertext struct {
	Seed []byte
	G1   []bn254.G1Affine
	G2   []bn254.G2Affine
	G2a  []bn254.G2Affine
	Ka   bn254.GT // [alpha * kappa]
	Msg  []byte   // the message XOR a pad derived from [kappa]
}

// layout gives the position of each named element in the flat lists.
type layout struct {
	par               Params
	n1, nu, n         int // N+1, coset size, forms
	delta, deltaPrime int // chunk lengths Delta and Delta'
	jQuo, jRem        int // chunk counts J and J'
	remIdx            []int
	nRem              int
}

func (pp *Public) layout() layout {
	l := layout{
		par:        pp.Par,
		n1:         pp.S.N + 1,
		nu:         pp.Nu,
		n:          pp.Par.NForms(),
		delta:      pp.Delta,
		deltaPrime: pp.DeltaPrime,
		jQuo:       pp.Par.JQuo(),
		jRem:       pp.Par.JRem(),
	}
	l.remIdx = make([]int, pp.DeltaPrime)
	for k := range l.remIdx {
		if k%pp.Nu == 0 {
			l.remIdx[k] = -1
			continue
		}
		l.remIdx[k] = l.nRem
		l.nRem++
	}
	return l
}

// G1: left factors, cancellation column, quotient powers, remainder powers.
func (l layout) f(k1, i, coord int) int { return (k1*l.n1+i)*2 + coord }
func (l layout) y(i int) int            { return 2*l.par.K1*l.n1 + i }
func (l layout) pquo(k int) int         { return (2*l.par.K1+1)*l.n1 + k }
func (l layout) premBase() int          { return (2*l.par.K1+1)*l.n1 + l.delta }
func (l layout) prem(k int) int         { return l.premBase() + l.remIdx[k] }
func (l layout) lenG1() int             { return l.premBase() + l.nRem }

// G2: right factors, search bases, quotient and remainder bases (chunked), tie
// bases, cross bases.
func (l layout) h(leg, j, coord int) int { return (leg*l.n1+j)*2 + coord }
func (l layout) s(leg int) int           { return 2*l.par.legs()*l.n1 + leg }
func (l layout) bquo(cell, j int) int    { return l.s(l.par.legs()) + j*l.par.Cells() + cell }
func (l layout) brem(cell, j int) int    { return l.bquo(0, l.jQuo) + j*l.par.Cells() + cell }

// tie(a, e) for a in 0..2 and e in 0..n-2.
func (l layout) tie(a, e int) int { return l.brem(0, l.jRem) + a*(l.n-1) + e }

// The five cross families, (a, iota) with iota = +1 or -1; (1, -1) does not
// occur.
const (
	cross1Plus = iota
	cross2Plus
	cross2Minus
	cross3Plus
	cross3Minus
	crossFamilies
)

// cross(fam, e) for e in 0..2n-2.
func (l layout) cross(fam, e int) int { return l.tie(3, 0) + fam*(2*l.n-1) + e }
func (l layout) lenG2() int           { return l.cross(crossFamilies, 0) }

func randNonzero() fr.Element {
	var x fr.Element
	for {
		if _, err := x.SetRandom(); err != nil {
			panic(err)
		}
		if !x.IsZero() {
			return x
		}
	}
}

// randRange returns a uniform integer in {2, ..., g+1}.
func randRange(bigG *big.Int) int64 {
	v, err := rand.Int(rand.Reader, bigG)
	if err != nil {
		panic(err)
	}
	return v.Int64() + 2
}

// sampleR is the centered sampler of Definition 5.3, returned as field
// elements.
func sampleR(N int, g int64) []fr.Element {
	r := make([]fr.Element, N+1)
	bigG := big.NewInt(g)
	sum := new(big.Int)
	var tmp big.Int
	for i := 1; i <= N; i++ {
		v := randRange(bigG)
		sum.Add(sum, tmp.SetInt64(v))
		r[i].SetInt64(v)
	}
	// r0 = ceil(N*(g+1)/2) + r* - floor(sum/2)
	a := new(big.Int).Mul(big.NewInt(int64(N)), big.NewInt(g+1))
	a.Add(a, big.NewInt(1))
	a.Rsh(a, 1)
	halfSum := sum.Rsh(sum, 1)
	r0 := a.Add(a, tmp.SetInt64(randRange(bigG)))
	r0.Sub(r0, halfSum)
	r[0].SetBigInt(r0)
	return r
}

func gtC0Bytes(k *bn254.GT) [192]byte {
	var out [192]byte
	coords := [6][32]byte{
		k.C0.B0.A0.Bytes(),
		k.C0.B0.A1.Bytes(),
		k.C0.B1.A0.Bytes(),
		k.C0.B1.A1.Bytes(),
		k.C0.B2.A0.Bytes(),
		k.C0.B2.A1.Bytes(),
	}
	for i, c := range coords {
		copy(out[i*32:(i+1)*32], c[:])
	}
	return out
}

// keyPadFor is the key oracle: a pad of the given length from an element of GT
// (Appendix A Figure 9) or, when signClass is true, from its unitary inverse
// class {V, V^-1} uniquely represented on BN254 by V.C0 in F_{p^6}
// (Section 6.4 and Praxis/Keys.lean's ClassName = Sym2 Label).
func keyPadFor(k *bn254.GT, length int, signClass bool) []byte {
	var material []byte
	domain := "praxis-demo/key"
	if signClass {
		domain = "praxis-demo/sign-class-key"
		c0 := gtC0Bytes(k)
		material = c0[:]
	} else {
		kb := k.Bytes()
		material = kb[:]
	}
	out := make([]byte, 0, length+sha256.Size)
	var ctr [4]byte
	for i := uint32(0); len(out) < length; i++ {
		binary.BigEndian.PutUint32(ctr[:], i)
		h := sha256.New()
		h.Write([]byte(domain))
		h.Write(ctr[:])
		h.Write(material)
		out = h.Sum(out)
	}
	return out[:length]
}

func keyPad(k *bn254.GT, length int) []byte {
	return keyPadFor(k, length, false)
}

// encCoins bundles the scalar coins of Figure 9 (lines 2-4) / Praxis/Enc.lean's Coins.
type encCoins struct {
	r, y                  []fr.Element
	tau, omega12, omega22 fr.Element
	alpha, pi             fr.Element
	sKind                 [3]fr.Element // (bE, bO, bV) in Praxis/Enc.lean
	ups                   fr.Element    // u in Praxis/Enc.lean
	zeta, zeta1, zeta2    fr.Element    // (zeta, zeta', zeta4) in Praxis/Enc.lean
	eta                   [3]fr.Element // (c1, c2, c3) in Praxis/Enc.lean
	eps                   fr.Element
}

func xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// Enc encrypts msg to the system: any solution of the system decrypts.
func Enc(pp *Public, msg []byte) (*Ciphertext, error) {
	ct, _, err := EncDetailed(pp, msg)
	return ct, err
}

// EncDetailed encrypts msg to the system and returns telemetry alongside the ciphertext.
func EncDetailed(pp *Public, msg []byte) (*Ciphertext, EncReport, error) {
	if pp == nil {
		return nil, EncReport{}, fmt.Errorf("nil public parameters")
	}
	start := time.Now()
	par, N, f := pp.Par, pp.S.N, pp.fld
	n := par.NForms()
	l := pp.layout()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, EncReport{}, err
	}
	phi := par.forms(seed, N)

	// The coins (Figure 9, lines 2 to 4).
	r := sampleR(N, par.G)
	y := make([]fr.Element, N+1)
	for i := range y {
		if _, err := y[i].SetRandom(); err != nil {
			return nil, EncReport{}, err
		}
	}
	var tau, zpTau, omega12 fr.Element
	for {
		if _, err := tau.SetRandom(); err != nil {
			return nil, EncReport{}, err
		}
		if zpTau = pp.ZP.Eval(&tau); !zpTau.IsZero() {
			break
		}
	}
	if _, err := omega12.SetRandom(); err != nil {
		return nil, EncReport{}, err
	}
	omega22, alpha, pi := randNonzero(), randNonzero(), randNonzero()
	sKind := [3]fr.Element{randNonzero(), randNonzero(), randNonzero()}
	ups := randNonzero()
	zeta, zeta1, zeta2 := randNonzero(), randNonzero(), randNonzero()
	eta := [3]fr.Element{randNonzero(), randNonzero(), randNonzero()}

	// eps must keep every left scalar 1 + eps*omega^(2*k1) nonzero.
	omega2 := pow(&f.omega, 2)
	var eps, one fr.Element
	one.SetOne()
	onePlus := make([]fr.Element, par.K1)
pick:
	for {
		eps = randNonzero()
		var w2 fr.Element
		w2.SetOne()
		for k1 := 0; k1 < par.K1; k1++ {
			onePlus[k1].Mul(&eps, &w2)
			onePlus[k1].Add(&onePlus[k1], &one)
			if onePlus[k1].IsZero() {
				continue pick
			}
			w2.Mul(&w2, &omega2)
		}
		break
	}

	c := encCoins{
		r:       r,
		y:       y,
		tau:     tau,
		omega12: omega12,
		omega22: omega22,
		alpha:   alpha,
		pi:      pi,
		sKind:   sKind,
		ups:     ups,
		zeta:    zeta,
		zeta1:   zeta1,
		zeta2:   zeta2,
		eta:     eta,
		eps:     eps,
	}
	s1, s2, kappa, ak := pp.computeEncScalars(phi, c)
	s2Both := make([]fr.Element, 2*len(s2))
	copy(s2Both, s2)
	s2a := s2Both[len(s2):]
	for i := range s2 {
		s2a[i].Mul(&s2[i], &alpha)
	}

	_, _, g1, g2 := bn254.Generators()
	g2Both := bn254.BatchScalarMultiplicationG2(&g2, s2Both)
	ct := &Ciphertext{
		Seed: seed,
		G1:   bn254.BatchScalarMultiplicationG1(&g1, s1),
		G2:   g2Both[:len(s2)],
		G2a:  g2Both[len(s2):],
	}
	gt, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		return nil, EncReport{}, err
	}
	var key bn254.GT
	key.Exp(gt, kappa.BigInt(new(big.Int)))
	ct.Ka.Exp(gt, ak.BigInt(new(big.Int)))
	ct.Msg = xor(msg, keyPadFor(&key, len(msg), par.SignClassKDF))
	g1Count, g2Count := pp.Counts()
	rep := EncReport{
		EncDur: time.Since(start),
		G1:     g1Count,
		G2:     g2Count,
		Bytes:  ct.Size(),
		J:      l.jQuo,
		Delta:  pp.Delta,
		JPrime: l.jRem,
		DeltaP: pp.DeltaPrime,
		Forms:  n,
		Cells:  par.Cells(),
	}
	return ct, rep, nil
}

// computeEncScalars evaluates Figure 9's G1, G2 (plain sector), key kappa, and
// alpha*kappa field exponents deterministically from forms phi and coins c.
func (pp *Public) computeEncScalars(phi [][]fr.Element, c encCoins) (s1, s2 []fr.Element, kappa, ak fr.Element) {
	par, N, f := pp.Par, pp.S.N, pp.fld
	n := par.NForms()
	l := pp.layout()
	r, y := c.r, c.y
	tau, omega12, omega22 := c.tau, c.omega12, c.omega22
	alpha, pi, sKind, ups := c.alpha, c.pi, c.sKind, c.ups
	zeta, zeta1, zeta2, eta, eps := c.zeta, c.zeta1, c.zeta2, c.eta, c.eps
	zpTau := pp.ZP.Eval(&tau)

	omega2 := pow(&f.omega, 2)
	var one, w2 fr.Element
	one.SetOne()
	w2.SetOne()
	onePlus := make([]fr.Element, par.K1)
	for k1 := 0; k1 < par.K1; k1++ {
		onePlus[k1].Mul(&eps, &w2)
		onePlus[k1].Add(&onePlus[k1], &one)
		w2.Mul(&w2, &omega2)
	}

	// Line 5: the scalars of the legs and of the cells.
	piK := make([]fr.Element, par.K1)
	for k1 := range piK {
		piK[k1] = pow(&ups, 2*k1)
		piK[k1].Mul(&piK[k1], &pi)
		piK[k1].Mul(&piK[k1], &onePlus[k1])
	}
	sLeg := make([]fr.Element, par.legs())
	for leg := range sLeg {
		sLeg[leg] = pow(&ups, par.legExp(leg))
		sLeg[leg].Mul(&sLeg[leg], &sKind[par.legKind(leg)])
	}

	// A_i(tau) and B_i(tau) through the Lagrange basis on the points.
	lag := make([]fr.Element, pp.D)
	for i := range lag {
		lag[i].Sub(&tau, &pp.Points[i])
	}
	lag = fr.BatchInvert(lag)
	aTau := make([]fr.Element, N+1)
	bTau := make([]fr.Element, N+1)
	var t fr.Element
	for i := range lag {
		lag[i].Mul(&lag[i], &pp.Weights[i])
		lag[i].Mul(&lag[i], &zpTau)
		for _, term := range pp.A[i] {
			t.Mul(&term.V, &lag[i])
			aTau[term.I].Add(&aTau[term.I], &t)
		}
		for _, term := range pp.B[i] {
			t.Mul(&term.V, &lag[i])
			bTau[term.I].Add(&bTau[term.I], &t)
		}
	}
	lrhoTau := lag[pp.rhoIndex()]
	zTau, z0Tau := pp.Z.Eval(&tau), pp.Z0.Eval(&tau)

	kappa.Mul(&piK[0], &sLeg[0])
	kappa.Mul(&kappa, &lrhoTau)
	ak.Mul(&alpha, &kappa)

	// Lines 6 and 7: the tie masks.
	var xMinus, xCirc, xPlus fr.Element
	xCirc.Neg(&ups)
	xPlus.Mul(&xCirc, &f.omega)
	xMinus.Div(&xCirc, &f.omega)
	zMinus, zCirc, zPlus := zAt(phi, &xMinus), zAt(phi, &xCirc), zAt(phi, &xPlus)
	var epsInv fr.Element
	epsInv.Inverse(&eps)
	mask := make([][]fr.Element, par.legs())
	for leg := range mask {
		mask[leg] = make([]fr.Element, N+1)
		kl := par.legExp(leg)
		p1 := pow(&ups, kl)
		p2 := pow(&xPlus, kl) // (-omega*upsilon)^kleg
		p2.Mul(&p2, &epsInv)
		var a, b fr.Element
		for j := 0; j <= N; j++ {
			if par.legKind(leg) == kindV {
				a.Mul(&eta[2], &zPlus[j])
				b.Mul(&eta[0], &zMinus[j])
				a.Sub(&a, &b)
				mask[leg][j].Mul(&p1, &a)
				continue
			}
			a.Mul(&eta[0], &zCirc[j])
			b.Mul(&eta[1], &zPlus[j])
			a.Add(&a, &b)
			a.Mul(&a, &p1)
			b.Mul(&eta[1], &zMinus[j])
			t.Mul(&eta[2], &zCirc[j])
			b.Add(&b, &t)
			b.Mul(&b, &p2)
			mask[leg][j].Sub(&a, &b)
		}
	}

	// The scalars of the G1 elements.
	s1 = make([]fr.Element, l.lenG1())
	for k1 := 0; k1 < par.K1; k1++ {
		for i := 0; i <= N; i++ {
			// pi_k1 * (y_i, A_i(tau)) * Omega
			s1[l.f(k1, i, 0)].Mul(&piK[k1], &y[i])
			t.Mul(&aTau[i], &omega22)
			var u fr.Element
			u.Mul(&y[i], &omega12)
			u.Add(&u, &t)
			s1[l.f(k1, i, 1)].Mul(&piK[k1], &u)
		}
	}
	for i := 0; i <= N; i++ {
		s1[l.y(i)].Mul(&zeta2, &y[i])
	}
	var tp fr.Element
	tp.SetOne()
	for k := 0; k < max(pp.Delta, pp.DeltaPrime); k++ {
		if k < pp.Delta {
			s1[l.pquo(k)].Mul(&zeta, &tp)
		}
		if k < pp.DeltaPrime && k%pp.Nu != 0 {
			s1[l.prem(k)].Mul(&zeta1, &tp)
		}
		tp.Mul(&tp, &tau)
	}

	// The scalars of the G2 elements.
	s2 = make([]fr.Element, l.lenG2())
	var o22Inv, o12Over22 fr.Element
	o22Inv.Inverse(&omega22)
	o12Over22.Mul(&omega12, &o22Inv)
	for leg := 0; leg < par.legs(); leg++ {
		for j := 0; j <= N; j++ {
			// Omega^-1 * (s(r_j + A_j(tau)) + mask_j, s(B_j(tau) - y_j))
			var h1, h2 fr.Element
			h1.Add(&r[j], &aTau[j])
			h1.Mul(&h1, &sLeg[leg])
			h1.Add(&h1, &mask[leg][j])
			h2.Sub(&bTau[j], &y[j])
			h2.Mul(&h2, &sLeg[leg])
			t.Mul(&h2, &o12Over22)
			s2[l.h(leg, j, 0)].Sub(&h1, &t)
			s2[l.h(leg, j, 1)].Mul(&h2, &o22Inv)
		}
		s2[l.s(leg)] = sLeg[leg]
	}
	var zetaInv, zeta1Inv, zeta2Inv, zKey fr.Element
	zetaInv.Inverse(&zeta)
	zeta1Inv.Inverse(&zeta1)
	zeta2Inv.Inverse(&zeta2)
	zKey.Sub(&tau, &pp.Points[pp.rhoIndex()])
	zKey.Mul(&zKey, &zTau) // Z(tau) * (tau - rho), for the key copy
	tauDelta := pow(&tau, pp.Delta)
	tauDeltaP := pow(&tau, pp.DeltaPrime)
	for k1 := 0; k1 < par.K1; k1++ {
		for leg := 0; leg < par.legs(); leg++ {
			cel := par.cell(k1, leg)
			var gamma fr.Element
			gamma.Mul(&piK[k1], &sLeg[leg])
			zc := zTau
			if cel == 0 {
				zc = zKey
			}
			var curQuo fr.Element
			curQuo.Mul(&gamma, &zc)
			curQuo.Mul(&curQuo, &zetaInv)
			for j := 0; j < l.jQuo; j++ {
				s2[l.bquo(cel, j)] = curQuo
				curQuo.Mul(&curQuo, &tauDelta)
			}
			var curRem fr.Element
			curRem.Mul(&gamma, &z0Tau)
			curRem.Mul(&curRem, &zeta1Inv)
			for j := 0; j < l.jRem; j++ {
				s2[l.brem(cel, j)] = curRem
				curRem.Mul(&curRem, &tauDeltaP)
			}
		}
	}
	// Tie bases carry P(upsilon) = upsilon^n - c0; cross bases carry eps or
	// its inverse instead.
	pUps := pow(&ups, n)
	pUps.Sub(&pUps, &f.c0)
	var base fr.Element
	base.Mul(&pi, &zeta2Inv)
	crossOf := [crossFamilies]struct {
		a   int
		eps *fr.Element
	}{{0, &eps}, {1, &eps}, {1, &epsInv}, {2, &eps}, {2, &epsInv}}
	tp.SetOne()
	for e := 0; e <= 2*n-2; e++ {
		if e <= n-2 {
			for a := 0; a < 3; a++ {
				x := &s2[l.tie(a, e)]
				x.Mul(&base, &eta[a])
				x.Mul(x, &pUps)
				x.Mul(x, &tp)
			}
		}
		for fam, cf := range crossOf {
			x := &s2[l.cross(fam, e)]
			x.Mul(&base, &eta[cf.a])
			x.Mul(x, cf.eps)
			x.Mul(x, &tp)
		}
		tp.Mul(&tp, &ups)
	}
	return s1, s2, kappa, ak
}

// Counts returns the number of elements of G1 and of G2 in a ciphertext of
// this system; the G2 count includes the alpha-copies.
func (pp *Public) Counts() (g1, g2 int) {
	l := pp.layout()
	return l.lenG1(), 2 * l.lenG2()
}

// PaperCounts is the same count from the formulas of Proposition 5.7.
func (pp *Public) PaperCounts() (g1, g2 int) {
	par, n := pp.Par, pp.Par.NForms()
	jQuo, jRem := par.JQuo(), par.JRem()
	N, nc := pp.S.N, pp.nc()
	n1 := (2*par.K1+1)*(N+1) + pp.Delta + (pp.Nu-1)*nc/jRem
	n2 := 6*par.K2*(N+1) + 3*par.K2 + 3*n/2*(jQuo+jRem) + 13*n - 8
	return n1, 2 * n2
}

// LeanCounts returns the element counts of Praxis/Published.lean (countG1, countG2),
// which include the 2*K1 total-sum elements (totL1, totL2) in G1 and the 12*K2
// total-sum elements (totR1, totR2 across .plain and .alpha) in G2 used in the
// Lean generic-group proof.
func (pp *Public) LeanCounts() (g1, g2 int) {
	pG1, pG2 := pp.PaperCounts()
	return pG1 + 2*pp.Par.K1, pG2 + 12*pp.Par.K2
}

// Size is the ciphertext's length in bytes with compressed points.
func (ct *Ciphertext) Size() int {
	return len(ct.Seed) + len(ct.Msg) + bn254.SizeOfGT +
		len(ct.G1)*bn254.SizeOfG1AffineCompressed +
		(len(ct.G2)+len(ct.G2a))*bn254.SizeOfG2AffineCompressed
}

func (ct *Ciphertext) check(pp *Public) error {
	if ct == nil {
		return fmt.Errorf("nil ciphertext")
	}
	l := pp.layout()
	if len(ct.G1) != l.lenG1() || len(ct.G2) != l.lenG2() || len(ct.G2a) != l.lenG2() {
		return fmt.Errorf("ciphertext does not match the system's shape")
	}
	return nil
}
