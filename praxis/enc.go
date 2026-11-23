package praxis

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

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
	par          Params
	n1, d, nu, n int // N+1, D, coset size, forms
	remIdx       []int
	nRem         int
}

func (pp *Public) layout() layout {
	l := layout{par: pp.Par, n1: pp.S.N + 1, d: pp.D, nu: pp.Nu, n: pp.Par.NForms()}
	l.remIdx = make([]int, pp.cosetLen())
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
func (l layout) prem(k int) int         { return (2*l.par.K1+1)*l.n1 + l.d + l.remIdx[k] }
func (l layout) lenG1() int             { return (2*l.par.K1+1)*l.n1 + l.d + l.nRem }

// G2: right factors, search bases, quotient and remainder bases, tie bases,
// cross bases.
func (l layout) h(leg, j, coord int) int { return (leg*l.n1+j)*2 + coord }
func (l layout) s(leg int) int           { return 2*l.par.legs()*l.n1 + leg }
func (l layout) bquo(cell int) int       { return l.s(l.par.legs()) + cell }
func (l layout) brem(cell int) int       { return l.bquo(l.par.Cells()) + cell }

// tie(a, e) for a in 0..2 and e in 0..n-2.
func (l layout) tie(a, e int) int { return l.brem(l.par.Cells()) + a*(l.n-1) + e }

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
func randRange(g int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(g))
	if err != nil {
		panic(err)
	}
	return v.Int64() + 2
}

// sampleR is the centered sampler of Definition 5.3, also returned as field
// elements. r[0] can be negative.
func sampleR(N int, g int64) []fr.Element {
	r := make([]fr.Element, N+1)
	var sum int64
	for i := 1; i <= N; i++ {
		v := randRange(g)
		sum += v
		r[i].SetInt64(v)
	}
	r0 := (int64(N)*(g+1)+1)/2 + randRange(g) - sum/2
	r[0].SetInt64(r0)
	return r
}

// keyPad is the key oracle: a pad of the given length from an element of GT.
func keyPad(k *bn254.GT, length int) []byte {
	kb := k.Bytes()
	out := make([]byte, 0, length+sha256.Size)
	var ctr [4]byte
	for i := uint32(0); len(out) < length; i++ {
		binary.BigEndian.PutUint32(ctr[:], i)
		h := sha256.New()
		h.Write([]byte("praxis-demo/key"))
		h.Write(ctr[:])
		h.Write(kb[:])
		out = h.Sum(out)
	}
	return out[:length]
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
	par, N, f := pp.Par, pp.S.N, pp.fld
	n := par.NForms()
	l := pp.layout()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	phi := par.forms(seed, N)

	// The coins (Figure 9, lines 2 to 4).
	r := sampleR(N, par.G)
	y := make([]fr.Element, N+1)
	for i := range y {
		if _, err := y[i].SetRandom(); err != nil {
			return nil, err
		}
	}
	var tau, zpTau, omega12 fr.Element
	for {
		tau.SetRandom()
		if zpTau = pp.ZP.Eval(&tau); !zpTau.IsZero() {
			break
		}
	}
	omega12.SetRandom()
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

	var kappa fr.Element
	kappa.Mul(&piK[0], &sLeg[0])
	kappa.Mul(&kappa, &lrhoTau)

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
	s1 := make([]fr.Element, l.lenG1())
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
	for k := 0; k < max(pp.D, pp.cosetLen()); k++ {
		if k < pp.D {
			s1[l.pquo(k)].Mul(&zeta, &tp)
		}
		if k < pp.cosetLen() && k%pp.Nu != 0 {
			s1[l.prem(k)].Mul(&zeta1, &tp)
		}
		tp.Mul(&tp, &tau)
	}

	// The scalars of the G2 elements.
	s2 := make([]fr.Element, l.lenG2())
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
	for k1 := 0; k1 < par.K1; k1++ {
		for leg := 0; leg < par.legs(); leg++ {
			c := par.cell(k1, leg)
			var gamma fr.Element
			gamma.Mul(&piK[k1], &sLeg[leg])
			zc := zTau
			if c == 0 {
				zc = zKey
			}
			s2[l.bquo(c)].Mul(&gamma, &zc)
			s2[l.bquo(c)].Mul(&s2[l.bquo(c)], &zetaInv)
			s2[l.brem(c)].Mul(&gamma, &z0Tau)
			s2[l.brem(c)].Mul(&s2[l.brem(c)], &zeta1Inv)
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
	s2a := make([]fr.Element, len(s2))
	for i := range s2 {
		s2a[i].Mul(&s2[i], &alpha)
	}

	_, _, g1, g2 := bn254.Generators()
	ct := &Ciphertext{
		Seed: seed,
		G1:   bn254.BatchScalarMultiplicationG1(&g1, s1),
		G2:   bn254.BatchScalarMultiplicationG2(&g2, s2),
		G2a:  bn254.BatchScalarMultiplicationG2(&g2, s2a),
	}
	gt, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		return nil, err
	}
	var key bn254.GT
	key.Exp(gt, kappa.BigInt(new(big.Int)))
	var ak fr.Element
	ak.Mul(&alpha, &kappa)
	ct.Ka.Exp(gt, ak.BigInt(new(big.Int)))
	ct.Msg = xor(msg, keyPad(&key, len(msg)))
	return ct, nil
}

// Counts returns the number of elements of G1 and of G2 in a ciphertext of
// this system; the G2 count includes the alpha-copies.
func (pp *Public) Counts() (g1, g2 int) {
	l := pp.layout()
	return l.lenG1(), 2 * l.lenG2()
}

// PaperCounts is the same count from the formulas of Proposition 5.7 with
// one chunk of powers.
func (pp *Public) PaperCounts() (g1, g2 int) {
	par, n := pp.Par, pp.Par.NForms()
	N, nc := pp.S.N, pp.nc()
	n1 := (2*par.K1+1)*(N+1) + pp.D + (pp.Nu-1)*nc
	n2 := 6*par.K2*(N+1) + 3*par.K2 + 3*n/2*2 + 13*n - 8
	return n1, 2 * n2
}

// Size is the ciphertext's length in bytes with compressed points.
func (ct *Ciphertext) Size() int {
	return len(ct.Seed) + len(ct.Msg) + bn254.SizeOfGT +
		len(ct.G1)*bn254.SizeOfG1AffineCompressed +
		(len(ct.G2)+len(ct.G2a))*bn254.SizeOfG2AffineCompressed
}

func (ct *Ciphertext) check(pp *Public) error {
	l := pp.layout()
	if len(ct.G1) != l.lenG1() || len(ct.G2) != l.lenG2() || len(ct.G2a) != l.lenG2() {
		return fmt.Errorf("ciphertext does not match the system's shape")
	}
	return nil
}
