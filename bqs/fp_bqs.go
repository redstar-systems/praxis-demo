package bqs

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Non-native BN254 F_p arithmetic inside a Boolean Quadratic System over BN254 F_q (= F_r).
//
// Each F_p element x in [0, p-1] is encoded as 254 Boolean unknowns in 4 radix-2^68 limbs:
//   x = x0 + 2^68*x1 + 2^136*x2 + 2^204*x3   (bit widths: 68, 68, 68, 50).
//
// Any multi-product F_p identity
//   sum_m gamma_m * A_m * B_m + sum_l delta_l * X_l + const == C (mod p)
// is proved over Z using exactly 3 BQS constraints via CRT(2^272, q):
//   Eq 1 (mod 2^136): S0 + 2^68 * S1            = 2^136 * t1
//   Eq 2 (mod 2^272): (S2 + t1) + 2^68 * S3     = 2^136 * t2
//   Eq 3 (mod q):     full(sum - C - K * p)     = 0 (mod q)
//
// Because gcd(2^272, q) = 1 and q * 2^272 > 2^525.6, whenever |E| < q * 2^272 / 2
// and |Eq1|, |Eq2| < q / 2 (both strictly asserted at compile time), E = 0 over Z holds
// with zero soundness error.

const (
	fpLimbBits = 68
	fpTotalBit = 254
)

var (
	bn254P       = new(big.Int).Set(fp.Modulus())
	bn254PMinus1 = new(big.Int).Sub(fp.Modulus(), big.NewInt(1))
	bn254Q       = new(big.Int).Set(fr.Modulus())
	bn254HalfQ   = new(big.Int).Rsh(fr.Modulus(), 1)
	bn254B       = new(big.Int).Lsh(big.NewInt(1), fpLimbBits)
	bn254B2      = new(big.Int).Lsh(big.NewInt(1), 2*fpLimbBits)
	bn254B4      = new(big.Int).Lsh(big.NewInt(1), 4*fpLimbBits)
	bn254CRTMax  = new(big.Int).Rsh(new(big.Int).Mul(fr.Modulus(), bn254B4), 1)

	bn254PLimbs [4]*big.Int
	bn254PModQ  fr.Element
	bn254BFr    fr.Element
	bn254B2Fr   fr.Element
	bn254Pow68  [4]fr.Element
	bn254TwistB [2]*big.Int // b' = 3 / (9 + u) in E2
)

// Exact 12x12 F_p matrices for E12 Frobenius maps and E12 bilinear multiplication,
// extracted directly from gnark-crypto/ecc/bn254 at init time (zero hand-typed tables).
var (
	e12Frob1Mat [12][12]*big.Int
	e12Frob2Mat [12][12]*big.Int
	e12Frob3Mat [12][12]*big.Int
	// e12MulCoeffs[outCoord][i][j] is the small integer multiplier for a[i]*b[j] in (a*b)[outCoord].
	e12MulCoeffs [12][12][12]int64
	// g2PhiMat / g2PsiMat: exact F_p 2x2 matrices for E2 Frobenius maps used in final Miller lines.
	g2PhiXMat [2][2]*big.Int
	g2PhiYMat [2][2]*big.Int
	g2PsiXMat [2][2]*big.Int
	g2PsiYMat [2][2]*big.Int
)

func init() {
	mask68 := new(big.Int).Sub(bn254B, big.NewInt(1))
	for i := 0; i < 4; i++ {
		bn254PLimbs[i] = new(big.Int).And(new(big.Int).Rsh(bn254P, uint(i*fpLimbBits)), mask68)
		bn254Pow68[i].SetBigInt(new(big.Int).Lsh(big.NewInt(1), uint(i*fpLimbBits)))
	}
	bn254PModQ.SetBigInt(new(big.Int).Mod(bn254P, bn254Q))
	bn254BFr.SetBigInt(bn254B)
	bn254B2Fr.SetBigInt(bn254B2)

	// Extract b' = 3 / (9 + u) using gnark-crypto's G2 generator (y^2 - x^3 = b').
	_, _, _, g2Gen := bn254.Generators()
	var y2, x3, bTw bn254.E2
	y2.Square(&g2Gen.Y)
	x3.Square(&g2Gen.X).Mul(&x3, &g2Gen.X)
	bTw.Sub(&y2, &x3)
	bn254TwistB[0] = bTw.A0.BigInt(new(big.Int))
	bn254TwistB[1] = bTw.A1.BigInt(new(big.Int))

	// Extract exact E12 Frobenius matrices (Frob1, Frob2, Frob3).
	for col := 0; col < 12; col++ {
		var basis bn254.E12
		setE12Coord(&basis, col, big.NewInt(1))
		var f1, f2, f3 bn254.E12
		f1.Frobenius(&basis)
		f2.FrobeniusSquare(&basis)
		f3.FrobeniusCube(&basis)
		c1 := getE12Coords(&f1)
		c2 := getE12Coords(&f2)
		c3 := getE12Coords(&f3)
		for row := 0; row < 12; row++ {
			e12Frob1Mat[row][col] = c1[row]
			e12Frob2Mat[row][col] = c2[row]
			e12Frob3Mat[row][col] = c3[row]
		}
	}

	// Extract exact small signed integer coefficients for E12 multiplication.
	halfP := new(big.Int).Rsh(bn254P, 1)
	for i := 0; i < 12; i++ {
		var ei bn254.E12
		setE12Coord(&ei, i, big.NewInt(1))
		for j := 0; j < 12; j++ {
			var ej, prod bn254.E12
			setE12Coord(&ej, j, big.NewInt(1))
			prod.Mul(&ei, &ej)
			coords := getE12Coords(&prod)
			for r := 0; r < 12; r++ {
				v := coords[r]
				if v.Sign() == 0 {
					continue
				}
				if v.Cmp(halfP) > 0 {
					v = new(big.Int).Sub(v, bn254P)
				}
				if !v.IsInt64() {
					panic("unexpected non-small E12 multiplication basis coefficient")
				}
				e12MulCoeffs[r][i][j] = v.Int64()
			}
		}
	}

	// Extract exact G2 Frobenius Q1 = phi(Q) and Q2 = -psi(Q) 2x2 matrices over F_p.
	// Matches gnark-crypto/ecc/bn254/pairing.go:860-863:
	//   phiQ.X = Conj(Q.X) * NonResidue1Power2, phiQ.Y = Conj(Q.Y) * NonResidue1Power3
	//   psiQ.X = Q.X * NonResidue2Power2,       psiQ.Y = -(Q.Y * NonResidue2Power3)
	for col := 0; col < 2; col++ {
		var e bn254.E2
		if col == 0 {
			e.A0.SetOne()
		} else {
			e.A1.SetOne()
		}
		var px, py, sx, sy bn254.E2
		px.Conjugate(&e).MulByNonResidue1Power2(&px)
		py.Conjugate(&e).MulByNonResidue1Power3(&py)
		sx.MulByNonResidue2Power2(&e)
		sy.MulByNonResidue2Power3(&e).Neg(&sy)

		g2PhiXMat[0][col] = px.A0.BigInt(new(big.Int))
		g2PhiXMat[1][col] = px.A1.BigInt(new(big.Int))
		g2PhiYMat[0][col] = py.A0.BigInt(new(big.Int))
		g2PhiYMat[1][col] = py.A1.BigInt(new(big.Int))
		g2PsiXMat[0][col] = sx.A0.BigInt(new(big.Int))
		g2PsiXMat[1][col] = sx.A1.BigInt(new(big.Int))
		g2PsiYMat[0][col] = sy.A0.BigInt(new(big.Int))
		g2PsiYMat[1][col] = sy.A1.BigInt(new(big.Int))
	}
}

func getE12Coords(e *bn254.E12) [12]*big.Int {
	return [12]*big.Int{
		e.C0.B0.A0.BigInt(new(big.Int)),
		e.C0.B0.A1.BigInt(new(big.Int)),
		e.C0.B1.A0.BigInt(new(big.Int)),
		e.C0.B1.A1.BigInt(new(big.Int)),
		e.C0.B2.A0.BigInt(new(big.Int)),
		e.C0.B2.A1.BigInt(new(big.Int)),
		e.C1.B0.A0.BigInt(new(big.Int)),
		e.C1.B0.A1.BigInt(new(big.Int)),
		e.C1.B1.A0.BigInt(new(big.Int)),
		e.C1.B1.A1.BigInt(new(big.Int)),
		e.C1.B2.A0.BigInt(new(big.Int)),
		e.C1.B2.A1.BigInt(new(big.Int)),
	}
}

func setE12Coord(e *bn254.E12, idx int, v *big.Int) {
	switch idx {
	case 0:
		e.C0.B0.A0.SetBigInt(v)
	case 1:
		e.C0.B0.A1.SetBigInt(v)
	case 2:
		e.C0.B1.A0.SetBigInt(v)
	case 3:
		e.C0.B1.A1.SetBigInt(v)
	case 4:
		e.C0.B2.A0.SetBigInt(v)
	case 5:
		e.C0.B2.A1.SetBigInt(v)
	case 6:
		e.C1.B0.A0.SetBigInt(v)
	case 7:
		e.C1.B0.A1.SetBigInt(v)
	case 8:
		e.C1.B1.A0.SetBigInt(v)
	case 9:
		e.C1.B1.A1.SetBigInt(v)
	case 10:
		e.C1.B2.A0.SetBigInt(v)
	case 11:
		e.C1.B2.A1.SetBigInt(v)
	}
}

func e12FromCoords(c [12]*big.Int) bn254.E12 {
	var e bn254.E12
	for i := 0; i < 12; i++ {
		setE12Coord(&e, i, c[i])
	}
	return e
}

// FpVar represents a non-native BN254 F_p element inside a BQS over F_q.
type FpVar struct {
	Limbs      [4]Vec
	Full       Vec
	Val        *big.Int // witness value in [0, p-1] (nil during compile-only mode)
	Const      bool
	ConstLimbs [4]*big.Int
}

// E2Var represents an element of BN254 F_{p^2} = F_p[u]/(u^2+1).
type E2Var struct {
	A0, A1 FpVar
}

// E12Var represents an element of BN254 F_{p^{12}} as 12 F_p coordinates in gnark-crypto tower order.
type E12Var struct {
	C [12]FpVar
}

// G1Var represents an affine BN254 G1 point.
type G1Var struct {
	X, Y FpVar
}

// G2Var represents an affine BN254 G2 point.
type G2Var struct {
	X, Y E2Var
}

// FpQuadTerm is coeff * A * B in a modular F_p constraint.
type FpQuadTerm struct {
	Coeff int64
	A, B  FpVar
}

// FpLinTerm is coeff * X in a modular F_p constraint.
type FpLinTerm struct {
	Coeff int64
	X     FpVar
}

// FpBuilder incrementally constructs a bqs.System and (when synth=true) the exact
// Boolean witness vector w []bool in lockstep.
type FpBuilder struct {
	N           int
	Constraints []Constraint
	synth       bool
	W           []bool // length N+1, W[0] = true when synth=true
}

// NewFpBuilder creates a BQS builder. If synth is true, it records exact Boolean witness bits.
func NewFpBuilder(synth bool) *FpBuilder {
	b := &FpBuilder{synth: synth}
	if synth {
		b.W = []bool{true}
	}
	return b
}

// System finalizes and validates the constructed BQS.
func (b *FpBuilder) System() (*System, error) {
	sys := &System{N: b.N, Constraints: b.Constraints}
	if err := sys.Validate(); err != nil {
		return nil, err
	}
	return sys, nil
}

// allocBits allocates nBits Boolean unknowns representing a non-negative integer val < 2^nBits,
// returning its linear form Vec over F_q.
func (b *FpBuilder) allocBits(nBits int, val *big.Int) Vec {
	if nBits <= 0 {
		return nil
	}
	if b.synth && (val == nil || val.Sign() < 0 || val.BitLen() > nBits) {
		panic(fmt.Sprintf("bqs fp allocBits: value %v does not fit in %d unsigned bits", val, nBits))
	}
	v := make(Vec, nBits)
	var pow2 fr.Element
	pow2.SetOne()
	var two fr.Element
	two.SetUint64(2)
	for i := 0; i < nBits; i++ {
		b.N++
		v[i] = Term{I: b.N, V: pow2}
		if b.synth {
			b.W = append(b.W, val.Bit(i) == 1)
		}
		pow2.Mul(&pow2, &two)
	}
	return v
}

// allocLimbs allocates a non-negative integer of totalBits split into 4 limbs:
// (68, 68, 68, totalBits-204).
func (b *FpBuilder) allocLimbs(totalBits int, val *big.Int) ([4]Vec, Vec) {
	var limbs [4]Vec
	var full Vec
	mask68 := new(big.Int).Sub(bn254B, big.NewInt(1))
	widths := [4]int{fpLimbBits, fpLimbBits, fpLimbBits, totalBits - 3*fpLimbBits}
	for li := 0; li < 4; li++ {
		if widths[li] <= 0 {
			continue
		}
		var lv *big.Int
		if b.synth {
			lv = new(big.Int).Rsh(val, uint(li*fpLimbBits))
			if li < 3 {
				lv.And(lv, mask68)
			}
		}
		limbs[li] = b.allocBits(widths[li], lv)
		for _, t := range limbs[li] {
			var scaled fr.Element
			scaled.Mul(&t.V, &bn254Pow68[li])
			full = append(full, Term{I: t.I, V: scaled})
		}
	}
	return limbs, full
}

// NewFpVar allocates a 254-bit non-native F_p witness variable.
func (b *FpBuilder) NewFpVar(val *big.Int) FpVar {
	var vMod *big.Int
	if b.synth {
		vMod = new(big.Int).Mod(val, bn254P)
	}
	limbs, full := b.allocLimbs(fpTotalBit, vMod)
	return FpVar{Limbs: limbs, Full: full, Val: vMod}
}

// ConstFp creates a constant F_p element (0 unknowns).
func (b *FpBuilder) ConstFp(val *big.Int) FpVar {
	v := new(big.Int).Mod(val, bn254P)
	mask68 := new(big.Int).Sub(bn254B, big.NewInt(1))
	var limbs [4]Vec
	var cLimbs [4]*big.Int
	for i := 0; i < 4; i++ {
		lv := new(big.Int).Rsh(v, uint(i*fpLimbBits))
		if i < 3 {
			lv.And(lv, mask68)
		}
		cLimbs[i] = lv
		if lv.Sign() != 0 {
			var fe fr.Element
			fe.SetBigInt(lv)
			limbs[i] = Vec{{I: 0, V: fe}}
		}
	}
	var full Vec
	if v.Sign() != 0 {
		var fe fr.Element
		fe.SetBigInt(new(big.Int).Mod(v, bn254Q))
		full = Vec{{I: 0, V: fe}}
	}
	return FpVar{Limbs: limbs, Full: full, Val: v, Const: true, ConstLimbs: cLimbs}
}

func (b *FpBuilder) NewE2Var(e bn254.E2) E2Var {
	if !b.synth {
		return E2Var{A0: b.NewFpVar(nil), A1: b.NewFpVar(nil)}
	}
	return E2Var{
		A0: b.NewFpVar(e.A0.BigInt(new(big.Int))),
		A1: b.NewFpVar(e.A1.BigInt(new(big.Int))),
	}
}

func (b *FpBuilder) ConstE2(e bn254.E2) E2Var {
	return E2Var{
		A0: b.ConstFp(e.A0.BigInt(new(big.Int))),
		A1: b.ConstFp(e.A1.BigInt(new(big.Int))),
	}
}

func (b *FpBuilder) NewE12Var(e bn254.E12) E12Var {
	var out E12Var
	var coords [12]*big.Int
	if b.synth {
		coords = getE12Coords(&e)
	}
	for i := 0; i < 12; i++ {
		out.C[i] = b.NewFpVar(coords[i])
	}
	return out
}

func (b *FpBuilder) ConstE12(e bn254.E12) E12Var {
	var out E12Var
	coords := getE12Coords(&e)
	for i := 0; i < 12; i++ {
		out.C[i] = b.ConstFp(coords[i])
	}
	return out
}

func (b *FpBuilder) NewG1Var(p bn254.G1Affine) G1Var {
	if !b.synth {
		return G1Var{X: b.NewFpVar(nil), Y: b.NewFpVar(nil)}
	}
	return G1Var{
		X: b.NewFpVar(p.X.BigInt(new(big.Int))),
		Y: b.NewFpVar(p.Y.BigInt(new(big.Int))),
	}
}

func (b *FpBuilder) ConstG1(p bn254.G1Affine) G1Var {
	return G1Var{
		X: b.ConstFp(p.X.BigInt(new(big.Int))),
		Y: b.ConstFp(p.Y.BigInt(new(big.Int))),
	}
}

func (b *FpBuilder) NewG2Var(q bn254.G2Affine) G2Var {
	if !b.synth {
		return G2Var{X: b.NewE2Var(bn254.E2{}), Y: b.NewE2Var(bn254.E2{})}
	}
	return G2Var{X: b.NewE2Var(q.X), Y: b.NewE2Var(q.Y)}
}

func scaleVec(v Vec, c fr.Element) Vec {
	if len(v) == 0 || c.IsZero() {
		return nil
	}
	out := make(Vec, len(v))
	for i, t := range v {
		out[i].I = t.I
		out[i].V.Mul(&t.V, &c)
	}
	return out
}

func mergeVec(parts ...Vec) Vec {
	m := make(map[int]fr.Element)
	for _, v := range parts {
		for _, t := range v {
			cur := m[t.I]
			cur.Add(&cur, &t.V)
			m[t.I] = cur
		}
	}
	out := make(Vec, 0, len(m))
	for idx, val := range m {
		if !val.IsZero() {
			out = append(out, Term{I: idx, V: val})
		}
	}
	return out
}

func frInt64(x int64) fr.Element {
	var e fr.Element
	e.SetInt64(x)
	return e
}

func frBig(x *big.Int) fr.Element {
	var e fr.Element
	e.SetBigInt(new(big.Int).Mod(x, bn254Q))
	return e
}

func maxValOf(v FpVar) *big.Int {
	if v.Const {
		return new(big.Int).Set(v.Val)
	}
	return new(big.Int).Set(bn254PMinus1)
}

func maxLimbOf(v FpVar, li int) *big.Int {
	if v.Const {
		return new(big.Int).Set(v.ConstLimbs[li])
	}
	if li < 3 {
		return new(big.Int).Sub(bn254B, big.NewInt(1))
	}
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), fpTotalBit-3*fpLimbBits), big.NewInt(1))
}

// AssertQuadModP adds 3 exact CRT BQS constraints proving over Z:
//
//	sum_m prods[m].Coeff * A_m * B_m + sum_l lins[l].Coeff * X_l + cnst == out (mod p).
//
// Constant * Variable products are automatically lowered to linear terms (zero extra products).
func (b *FpBuilder) AssertQuadModP(prods []FpQuadTerm, lins []FpLinTerm, cnst *big.Int, out FpVar) {
	if cnst == nil {
		cnst = big.NewInt(0)
	}
	// Filter zero-coeff terms and separate constant*constant into cnst.
	constAcc := new(big.Int).Set(cnst)
	var activeProds []FpQuadTerm
	for _, pt := range prods {
		if pt.Coeff == 0 {
			continue
		}
		if pt.A.Const && pt.B.Const {
			t := new(big.Int).Mul(pt.A.Val, pt.B.Val)
			t.Mul(t, big.NewInt(pt.Coeff))
			constAcc.Add(constAcc, t)
			continue
		}
		if pt.A.Const && pt.A.Val.Sign() == 0 || pt.B.Const && pt.B.Val.Sign() == 0 {
			continue
		}
		activeProds = append(activeProds, pt)
	}
	var activeLins []FpLinTerm
	for _, lt := range lins {
		if lt.Coeff == 0 {
			continue
		}
		if lt.X.Const {
			t := new(big.Int).Mul(lt.X.Val, big.NewInt(lt.Coeff))
			constAcc.Add(constAcc, t)
			continue
		}
		activeLins = append(activeLins, lt)
	}

	// Compute exact positive/negative bounds on sum - out to size K = (sum - out) / p tightly.
	maxPos := new(big.Int)
	maxNeg := new(big.Int)
	if constAcc.Sign() >= 0 {
		maxPos.Add(maxPos, constAcc)
	} else {
		maxNeg.Sub(maxNeg, constAcc)
	}
	maxNeg.Add(maxNeg, maxValOf(out))
	for _, pt := range activeProds {
		ub := new(big.Int).Mul(maxValOf(pt.A), maxValOf(pt.B))
		if pt.Coeff > 0 {
			ub.Mul(ub, big.NewInt(pt.Coeff))
			maxPos.Add(maxPos, ub)
		} else {
			ub.Mul(ub, big.NewInt(-pt.Coeff))
			maxNeg.Add(maxNeg, ub)
		}
	}
	for _, lt := range activeLins {
		ub := maxValOf(lt.X)
		if lt.Coeff > 0 {
			ub.Mul(ub, big.NewInt(lt.Coeff))
			maxPos.Add(maxPos, ub)
		} else {
			ub.Mul(ub, big.NewInt(-lt.Coeff))
			maxNeg.Add(maxNeg, ub)
		}
	}

	// K in [-kBias, kMax], encode kPos = K + kBias >= 0 in kBits bits.
	kBias := new(big.Int).Add(new(big.Int).Quo(maxNeg, bn254P), big.NewInt(1))
	kMax := new(big.Int).Quo(maxPos, bn254P)
	kRange := new(big.Int).Add(kMax, kBias)
	kBits := max(fpTotalBit, kRange.BitLen()+1)
	if kBits < 3*fpLimbBits+1 {
		kBits = 3*fpLimbBits + 1
	}

	// Verify exact CRT soundness bound: |E| < q * 2^272 / 2.
	kMaxAbs := new(big.Int).Set(kMax)
	if kBias.Cmp(kMaxAbs) > 0 {
		kMaxAbs.Set(kBias)
	}
	maxE := new(big.Int).Add(maxPos, maxNeg)
	maxE.Add(maxE, new(big.Int).Mul(kMaxAbs, bn254P))
	if maxE.Cmp(bn254CRTMax) >= 0 {
		panic(fmt.Sprintf("bqs AssertQuadModP: |E| bound (%d bits) exceeds CRT modulus q*2^272/2", maxE.BitLen()))
	}

	// Synthesize exact integer witness K, kPos, and carries t1, t2.
	var kPosVal *big.Int
	var sumCols [4]*big.Int
	if b.synth {
		exactSum := new(big.Int).Set(constAcc)
		for _, pt := range activeProds {
			t := new(big.Int).Mul(pt.A.Val, pt.B.Val)
			t.Mul(t, big.NewInt(pt.Coeff))
			exactSum.Add(exactSum, t)
		}
		for _, lt := range activeLins {
			t := new(big.Int).Mul(lt.X.Val, big.NewInt(lt.Coeff))
			exactSum.Add(exactSum, t)
		}
		exactSum.Sub(exactSum, out.Val)
		kVal, rem := new(big.Int).QuoRem(exactSum, bn254P, new(big.Int))
		if rem.Sign() != 0 {
			panic(fmt.Sprintf("bqs AssertQuadModP: witness does not satisfy equation mod p (rem=%v)", rem))
		}
		kPosVal = new(big.Int).Add(kVal, kBias)
		if kPosVal.Sign() < 0 || kPosVal.BitLen() > kBits {
			panic(fmt.Sprintf("bqs AssertQuadModP: kPos out of range (%d > %d bits)", kPosVal.BitLen(), kBits))
		}
		for c := 0; c < 4; c++ {
			sumCols[c] = new(big.Int)
		}
	}
	kLimbs, kFull := b.allocLimbs(kBits, kPosVal)

	// Absorb +kBias * p into constAcc so E = sum - out - kPos*p + (constAcc + kBias*p) = 0!
	adjConst := new(big.Int).Add(constAcc, new(big.Int).Mul(kBias, bn254P))
	// Decompose adjConst (signed) into signed limbs for columns 0..3 using Euclidean division by 2^68.
	// Note: adjConst = c0 + B*c1 + B^2*c2 + B^3*c3 + B^4*c4 (c4 does not affect mod B^4!).
	var adjConstLimbs [4]*big.Int
	{
		cur := new(big.Int).Set(adjConst)
		for c := 0; c < 4; c++ {
			qDiv, rMod := new(big.Int).QuoRem(cur, bn254B, new(big.Int))
			if rMod.Sign() < 0 {
				rMod.Add(rMod, bn254B)
				qDiv.Sub(qDiv, big.NewInt(1))
			}
			adjConstLimbs[c] = rMod
			cur = qDiv
		}
	}

	// Build limb column expressions S0..S3 (each is products + linearVec + const).
	var colProds [4][]Product
	var colLin [4][]Vec
	var colBound [4]*big.Int
	for c := 0; c < 4; c++ {
		colBound[c] = new(big.Int).Set(adjConstLimbs[c])
		if adjConstLimbs[c].Sign() != 0 {
			colLin[c] = append(colLin[c], Vec{{I: 0, V: frBig(adjConstLimbs[c])}})
		}
		if b.synth {
			sumCols[c].Add(sumCols[c], adjConstLimbs[c])
		}
	}

	// Helper to get limbs of witness values when synth=true.
	valLimbs := func(v *big.Int) [4]*big.Int {
		mask68 := new(big.Int).Sub(bn254B, big.NewInt(1))
		var outL [4]*big.Int
		for i := 0; i < 4; i++ {
			lv := new(big.Int).Rsh(v, uint(i*fpLimbBits))
			if i < 3 {
				lv.And(lv, mask68)
			}
			outL[i] = lv
		}
		return outL
	}

	// 1. Add quadratic terms prods[m].Coeff * A_m * B_m across columns 0..3.
	for _, pt := range activeProds {
		cAbs := pt.Coeff
		if cAbs < 0 {
			cAbs = -cAbs
		}
		cFr := frInt64(pt.Coeff)
		var aL, bL [4]*big.Int
		if b.synth {
			aL = valLimbs(pt.A.Val)
			bL = valLimbs(pt.B.Val)
		}
		for col := 0; col < 4; col++ {
			for i := 0; i <= col; i++ {
				j := col - i
				if len(pt.A.Limbs[i]) == 0 || len(pt.B.Limbs[j]) == 0 {
					continue
				}
				ub := new(big.Int).Mul(maxLimbOf(pt.A, i), maxLimbOf(pt.B, j))
				ub.Mul(ub, big.NewInt(cAbs))
				colBound[col].Add(colBound[col], ub)

				if b.synth {
					t := new(big.Int).Mul(aL[i], bL[j])
					t.Mul(t, big.NewInt(pt.Coeff))
					sumCols[col].Add(sumCols[col], t)
				}
				if pt.A.Const {
					var sc fr.Element
					sc.Mul(&cFr, &pt.A.Limbs[i][0].V)
					colLin[col] = append(colLin[col], scaleVec(pt.B.Limbs[j], sc))
				} else if pt.B.Const {
					var sc fr.Element
					sc.Mul(&cFr, &pt.B.Limbs[j][0].V)
					colLin[col] = append(colLin[col], scaleVec(pt.A.Limbs[i], sc))
				} else {
					colProds[col] = append(colProds[col], Product{
						A: scaleVec(pt.A.Limbs[i], cFr),
						B: pt.B.Limbs[j],
					})
				}
			}
		}
	}

	// 2. Add linear terms lins[l].Coeff * X_l across columns 0..3.
	for _, lt := range activeLins {
		cAbs := lt.Coeff
		if cAbs < 0 {
			cAbs = -cAbs
		}
		cFr := frInt64(lt.Coeff)
		var xL [4]*big.Int
		if b.synth {
			xL = valLimbs(lt.X.Val)
		}
		for col := 0; col < 4; col++ {
			if len(lt.X.Limbs[col]) == 0 {
				continue
			}
			ub := new(big.Int).Mul(maxLimbOf(lt.X, col), big.NewInt(cAbs))
			colBound[col].Add(colBound[col], ub)
			if b.synth {
				t := new(big.Int).Mul(xL[col], big.NewInt(lt.Coeff))
				sumCols[col].Add(sumCols[col], t)
			}
			colLin[col] = append(colLin[col], scaleVec(lt.X.Limbs[col], cFr))
		}
	}

	// 3. Subtract out and kPos * p across columns 0..3.
	var outL, kL [4]*big.Int
	if b.synth {
		outL = valLimbs(out.Val)
		kL = valLimbs(kPosVal)
	}
	var negOne fr.Element
	negOne.SetInt64(-1)
	kMaxLimb := [4]*big.Int{
		new(big.Int).Sub(bn254B, big.NewInt(1)),
		new(big.Int).Sub(bn254B, big.NewInt(1)),
		new(big.Int).Sub(bn254B, big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(kBits-3*fpLimbBits)), big.NewInt(1)),
	}
	for col := 0; col < 4; col++ {
		if len(out.Limbs[col]) > 0 {
			colBound[col].Add(colBound[col], maxLimbOf(out, col))
			colLin[col] = append(colLin[col], scaleVec(out.Limbs[col], negOne))
			if b.synth {
				sumCols[col].Sub(sumCols[col], outL[col])
			}
		}
		for i := 0; i <= col; i++ {
			j := col - i
			if len(kLimbs[i]) == 0 || bn254PLimbs[j].Sign() == 0 {
				continue
			}
			ub := new(big.Int).Mul(kMaxLimb[i], bn254PLimbs[j])
			colBound[col].Add(colBound[col], ub)
			var negPj fr.Element
			negPj.SetBigInt(bn254PLimbs[j])
			negPj.Neg(&negPj)
			colLin[col] = append(colLin[col], scaleVec(kLimbs[i], negPj))
			if b.synth {
				t := new(big.Int).Mul(kL[i], bn254PLimbs[j])
				sumCols[col].Sub(sumCols[col], t)
			}
		}
	}

	// Eq 1 (mod 2^136): S0 + B*S1 = B^2 * t1.
	eq1Bound := new(big.Int).Add(colBound[0], new(big.Int).Mul(bn254B, colBound[1]))
	if eq1Bound.Cmp(bn254HalfQ) >= 0 {
		panic(fmt.Sprintf("bqs AssertQuadModP: Eq1 bound (%d bits) exceeds q/2", eq1Bound.BitLen()))
	}
	t1Bias := new(big.Int).Add(new(big.Int).Quo(eq1Bound, bn254B2), big.NewInt(1))
	t1Bits := new(big.Int).Lsh(t1Bias, 1).BitLen() + 1
	var t1Val, t1PosVal *big.Int
	if b.synth {
		lhs1 := new(big.Int).Add(sumCols[0], new(big.Int).Mul(bn254B, sumCols[1]))
		var rem *big.Int
		t1Val, rem = new(big.Int).QuoRem(lhs1, bn254B2, new(big.Int))
		if rem.Sign() != 0 {
			panic(fmt.Sprintf("bqs AssertQuadModP: Eq1 not divisible by 2^136 (rem=%v)", rem))
		}
		t1PosVal = new(big.Int).Add(t1Val, t1Bias)
	}
	t1PosVec := b.allocBits(t1Bits, t1PosVal)

	// Combine products and linear terms for Eq 1:
	// sum(prods0) + B*sum(prods1) = B^2*(t1Pos - t1Bias) - lin0 - B*lin1
	var eq1Prods []Product
	eq1Prods = append(eq1Prods, colProds[0]...)
	for _, p := range colProds[1] {
		eq1Prods = append(eq1Prods, Product{A: scaleVec(p.A, bn254BFr), B: p.B})
	}
	var eq1RHS []Vec
	eq1RHS = append(eq1RHS, scaleVec(t1PosVec, bn254B2Fr))
	{
		negBias := new(big.Int).Mul(t1Bias, bn254B2)
		negBias.Neg(negBias)
		eq1RHS = append(eq1RHS, Vec{{I: 0, V: frBig(negBias)}})
	}
	for _, lv := range colLin[0] {
		eq1RHS = append(eq1RHS, scaleVec(lv, negOne))
	}
	var negB fr.Element
	negB.Neg(&bn254BFr)
	for _, lv := range colLin[1] {
		eq1RHS = append(eq1RHS, scaleVec(lv, negB))
	}
	if len(eq1Prods) == 0 {
		eq1Prods = []Product{{}}
	}
	b.Constraints = append(b.Constraints, Constraint{Products: eq1Prods, C: mergeVec(eq1RHS...)})

	// Eq 2 (mod 2^272): (S2 + t1) + B*S3 = B^2 * t2.
	eq2Bound := new(big.Int).Add(colBound[2], t1Bias)
	eq2Bound.Add(eq2Bound, new(big.Int).Mul(bn254B, colBound[3]))
	if eq2Bound.Cmp(bn254HalfQ) >= 0 {
		panic(fmt.Sprintf("bqs AssertQuadModP: Eq2 bound (%d bits) exceeds q/2", eq2Bound.BitLen()))
	}
	t2Bias := new(big.Int).Add(new(big.Int).Quo(eq2Bound, bn254B2), big.NewInt(1))
	t2Bits := new(big.Int).Lsh(t2Bias, 1).BitLen() + 1
	var t2PosVal *big.Int
	if b.synth {
		lhs2 := new(big.Int).Add(sumCols[2], t1Val)
		lhs2.Add(lhs2, new(big.Int).Mul(bn254B, sumCols[3]))
		t2Val, rem := new(big.Int).QuoRem(lhs2, bn254B2, new(big.Int))
		if rem.Sign() != 0 {
			panic(fmt.Sprintf("bqs AssertQuadModP: Eq2 not divisible by 2^136 (rem=%v)", rem))
		}
		t2PosVal = new(big.Int).Add(t2Val, t2Bias)
	}
	t2PosVec := b.allocBits(t2Bits, t2PosVal)

	var eq2Prods []Product
	eq2Prods = append(eq2Prods, colProds[2]...)
	for _, p := range colProds[3] {
		eq2Prods = append(eq2Prods, Product{A: scaleVec(p.A, bn254BFr), B: p.B})
	}
	var eq2RHS []Vec
	eq2RHS = append(eq2RHS, scaleVec(t2PosVec, bn254B2Fr))
	{
		// RHS has -B^2*t2Bias + t1Bias (moving t1 = t1Pos - t1Bias from LHS to RHS gives -t1Pos + t1Bias).
		c := new(big.Int).Mul(t2Bias, bn254B2)
		c.Neg(c)
		c.Add(c, t1Bias)
		eq2RHS = append(eq2RHS, Vec{{I: 0, V: frBig(c)}})
	}
	eq2RHS = append(eq2RHS, scaleVec(t1PosVec, negOne))
	for _, lv := range colLin[2] {
		eq2RHS = append(eq2RHS, scaleVec(lv, negOne))
	}
	for _, lv := range colLin[3] {
		eq2RHS = append(eq2RHS, scaleVec(lv, negB))
	}
	if len(eq2Prods) == 0 {
		eq2Prods = []Product{{}}
	}
	b.Constraints = append(b.Constraints, Constraint{Products: eq2Prods, C: mergeVec(eq2RHS...)})

	// Eq 3 (mod q): sum_m coeff * A_full * B_full + sum_l coeff * X_full + adjConst - out_full - kPos_full * p == 0 (mod q)
	// Written as: sum(varProds) = out_full + kPos_full*p - adjConst - sum(linFull)
	var eq3Prods []Product
	var eq3RHS []Vec
	eq3RHS = append(eq3RHS, out.Full)
	eq3RHS = append(eq3RHS, scaleVec(kFull, bn254PModQ))
	negAdjConst := new(big.Int).Neg(adjConst)
	eq3RHS = append(eq3RHS, Vec{{I: 0, V: frBig(negAdjConst)}})
	for _, pt := range activeProds {
		cFr := frInt64(pt.Coeff)
		if pt.A.Const {
			var sc fr.Element
			sc.Mul(&cFr, &pt.A.Full[0].V)
			sc.Neg(&sc)
			eq3RHS = append(eq3RHS, scaleVec(pt.B.Full, sc))
		} else if pt.B.Const {
			var sc fr.Element
			sc.Mul(&cFr, &pt.B.Full[0].V)
			sc.Neg(&sc)
			eq3RHS = append(eq3RHS, scaleVec(pt.A.Full, sc))
		} else {
			eq3Prods = append(eq3Prods, Product{
				A: scaleVec(pt.A.Full, cFr),
				B: pt.B.Full,
			})
		}
	}
	for _, lt := range activeLins {
		cFr := frInt64(-lt.Coeff)
		eq3RHS = append(eq3RHS, scaleVec(lt.X.Full, cFr))
	}
	if len(eq3Prods) == 0 {
		eq3Prods = []Product{{}}
	}
	b.Constraints = append(b.Constraints, Constraint{Products: eq3Prods, C: mergeVec(eq3RHS...)})
}

// --- High-level BN254 F_p, E2, E12, G1, G2 BQS operations ---

func (b *FpBuilder) FpMul(x, y FpVar) FpVar {
	var outVal *big.Int
	if b.synth {
		outVal = new(big.Int).Mul(x.Val, y.Val)
		outVal.Mod(outVal, bn254P)
	}
	out := b.NewFpVar(outVal)
	b.AssertQuadModP([]FpQuadTerm{{Coeff: 1, A: x, B: y}}, nil, nil, out)
	return out
}

func (b *FpBuilder) FpInv(x FpVar) FpVar {
	var invVal *big.Int
	if b.synth {
		invVal = new(big.Int).ModInverse(x.Val, bn254P)
		if invVal == nil {
			panic("bqs FpInv: zero input")
		}
	}
	inv := b.NewFpVar(invVal)
	b.AssertQuadModP([]FpQuadTerm{{Coeff: 1, A: x, B: inv}}, nil, nil, b.ConstFp(big.NewInt(1)))
	return inv
}

func (b *FpBuilder) FpNeg(x FpVar) FpVar {
	var negVal *big.Int
	if b.synth {
		negVal = new(big.Int).Sub(bn254P, x.Val)
		negVal.Mod(negVal, bn254P)
	}
	out := b.NewFpVar(negVal)
	b.AssertQuadModP(nil, []FpLinTerm{{Coeff: 1, X: x}, {Coeff: 1, X: out}}, nil, b.ConstFp(big.NewInt(0)))
	return out
}

func (b *FpBuilder) E2Mul(x, y E2Var) E2Var {
	var outVal bn254.E2
	if b.synth {
		var ex, ey bn254.E2
		ex.A0.SetBigInt(x.A0.Val)
		ex.A1.SetBigInt(x.A1.Val)
		ey.A0.SetBigInt(y.A0.Val)
		ey.A1.SetBigInt(y.A1.Val)
		outVal.Mul(&ex, &ey)
	}
	out := b.NewE2Var(outVal)
	// (a0 + a1*u)(b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: x.A0, B: y.A0},
		{Coeff: -1, A: x.A1, B: y.A1},
	}, nil, nil, out.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: x.A0, B: y.A1},
		{Coeff: 1, A: x.A1, B: y.A0},
	}, nil, nil, out.A1)
	return out
}

func (b *FpBuilder) E2MulByFp(x E2Var, s FpVar) E2Var {
	return E2Var{
		A0: b.FpMul(x.A0, s),
		A1: b.FpMul(x.A1, s),
	}
}

func (b *FpBuilder) E2AssertEqual(x, y E2Var) {
	b.AssertQuadModP(nil, []FpLinTerm{{Coeff: 1, X: x.A0}}, nil, y.A0)
	b.AssertQuadModP(nil, []FpLinTerm{{Coeff: 1, X: x.A1}}, nil, y.A1)
}

func (b *FpBuilder) E2LinearMap(x E2Var, mat [2][2]*big.Int) E2Var {
	var outVal bn254.E2
	if b.synth {
		v0 := new(big.Int).Add(
			new(big.Int).Mul(mat[0][0], x.A0.Val),
			new(big.Int).Mul(mat[0][1], x.A1.Val),
		)
		v1 := new(big.Int).Add(
			new(big.Int).Mul(mat[1][0], x.A0.Val),
			new(big.Int).Mul(mat[1][1], x.A1.Val),
		)
		v0.Mod(v0, bn254P)
		v1.Mod(v1, bn254P)
		outVal.A0.SetBigInt(v0)
		outVal.A1.SetBigInt(v1)
	}
	out := b.NewE2Var(outVal)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: b.ConstFp(mat[0][0]), B: x.A0},
		{Coeff: 1, A: b.ConstFp(mat[0][1]), B: x.A1},
	}, nil, nil, out.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: b.ConstFp(mat[1][0]), B: x.A0},
		{Coeff: 1, A: b.ConstFp(mat[1][1]), B: x.A1},
	}, nil, nil, out.A1)
	return out
}

func (b *FpBuilder) E12Mul(x, y E12Var) E12Var {
	var outVal bn254.E12
	if b.synth {
		var xc, yc [12]*big.Int
		for i := 0; i < 12; i++ {
			xc[i] = x.C[i].Val
			yc[i] = y.C[i].Val
		}
		ex := e12FromCoords(xc)
		ey := e12FromCoords(yc)
		outVal.Mul(&ex, &ey)
	}
	out := b.NewE12Var(outVal)
	b.AssertE12Mul(x, y, out)
	return out
}

func (b *FpBuilder) E12Square(x E12Var) E12Var {
	return b.E12Mul(x, x)
}

// AssertE12Mul asserts x * y == out in BN254 E12 using 12 multi-product F_p constraints (36 BQS rows total).
func (b *FpBuilder) AssertE12Mul(x, y, out E12Var) {
	for r := 0; r < 12; r++ {
		var prods []FpQuadTerm
		for i := 0; i < 12; i++ {
			for j := 0; j < 12; j++ {
				c := e12MulCoeffs[r][i][j]
				if c != 0 {
					prods = append(prods, FpQuadTerm{Coeff: c, A: x.C[i], B: y.C[j]})
				}
			}
		}
		b.AssertQuadModP(prods, nil, nil, out.C[r])
	}
}

// E12MulBy34 multiplies x by sparse E12 element (1, 0, 0, c3, c4, 0) in 12 F_p constraints.
func (b *FpBuilder) E12MulBy34(x E12Var, c3, c4 E2Var) E12Var {
	zero := b.ConstFp(big.NewInt(0))
	sparse := E12Var{
		C: [12]FpVar{
			b.ConstFp(big.NewInt(1)), zero,
			zero, zero,
			zero, zero,
			c3.A0, c3.A1,
			c4.A0, c4.A1,
			zero, zero,
		},
	}
	return b.E12Mul(x, sparse)
}

// E12FrobeniusMap applies an exact 12x12 F_p Frobenius linear map (Frob1, Frob2, or Frob3).
func (b *FpBuilder) E12FrobeniusMap(x E12Var, mat [12][12]*big.Int) E12Var {
	var out E12Var
	for r := 0; r < 12; r++ {
		var prods []FpQuadTerm
		var acc *big.Int
		if b.synth {
			acc = new(big.Int)
		}
		// Optimize exact identity / single-1 rows directly with zero extra unknowns!
		nonZero := 0
		onlyCol := -1
		for col := 0; col < 12; col++ {
			if mat[r][col].Sign() != 0 {
				nonZero++
				onlyCol = col
			}
		}
		if nonZero == 1 && mat[r][onlyCol].Cmp(big.NewInt(1)) == 0 {
			out.C[r] = x.C[onlyCol]
			continue
		}
		for col := 0; col < 12; col++ {
			if mat[r][col].Sign() == 0 {
				continue
			}
			prods = append(prods, FpQuadTerm{Coeff: 1, A: b.ConstFp(mat[r][col]), B: x.C[col]})
			if b.synth {
				acc.Add(acc, new(big.Int).Mul(mat[r][col], x.C[col].Val))
			}
		}
		if b.synth {
			acc.Mod(acc, bn254P)
		}
		out.C[r] = b.NewFpVar(acc)
		b.AssertQuadModP(prods, nil, nil, out.C[r])
	}
	return out
}

// AssertG1OnCurve asserts P.Y^2 == P.X^3 + 3 (mod p), which also rules out (0, 0).
func (b *FpBuilder) AssertG1OnCurve(p G1Var) {
	x2 := b.FpMul(p.X, p.X)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: p.Y, B: p.Y},
		{Coeff: -1, A: x2, B: p.X},
	}, nil, big.NewInt(-3), b.ConstFp(big.NewInt(0)))
}

// AssertG2OnTwist asserts Q.Y^2 == Q.X^3 + b' (mod p^2), ruling out (0, 0).
func (b *FpBuilder) AssertG2OnTwist(q G2Var) {
	x2 := b.E2Mul(q.X, q.X)
	x3 := b.E2Mul(x2, q.X)
	// q.Y^2 - x3 - b' == 0
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: q.Y.A0, B: q.Y.A0},
		{Coeff: -1, A: q.Y.A1, B: q.Y.A1},
	}, []FpLinTerm{{Coeff: -1, X: x3.A0}}, new(big.Int).Neg(bn254TwistB[0]), b.ConstFp(big.NewInt(0)))
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: q.Y.A0, B: q.Y.A1},
	}, []FpLinTerm{{Coeff: -1, X: x3.A1}}, new(big.Int).Neg(bn254TwistB[1]), b.ConstFp(big.NewInt(0)))
}
