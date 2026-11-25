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
// Each F_p element x in [0, p-1] is encoded as 254 Boolean unknowns in 5 radix-2^54 limbs:
//   x = x0 + 2^54*x1 + 2^108*x2 + 2^162*x3 + 2^216*x4   (bit widths: 54, 54, 54, 54, 38).
//
// Any multi-product F_p identity
//   sum_m gamma_m * A_m * B_m + sum_l delta_l * X_l + const == C (mod p)
// is proved over Z using at most 3 BQS constraints via CRT(2^270, q)
// (or 2 BQS constraints via CRT(2^162, q) for small linear identities):
//   Eq 1 (mod 2^162): S0 + 2^54*S1 + 2^108*S2 = 2^162 * t1
//   Eq 2 (mod 2^270): (S3 + t1) + 2^54*S4     = 2^108 * t2
//   Eq 3 (mod q):     full(sum - C - K * p)   = 0 (mod q)
//
// Because gcd(2^270, q) = 1 and q * 2^270 > 2^523.6, whenever adversarial bounds
// |E| < q * 2^270 / 2 (over all Boolean assignments x in [0, 2^254-1], kPos in [0, 2^kBits-1])
// and |Eq1|, |Eq2| < q / 2 (all strictly asserted at compile time), E = 0 over Z holds
// with zero soundness error.
//
// Compared to 4x68-bit limbs, 5x54-bit limbs shrink carry widths t1, t2 by ~28 bits per
// modular equation while keeping dense E12 multiplication at Fmax <= 60 (coset size nu = 64).

const (
	fpLimbs    = 5
	fpLimbBits = 54
	fpEq1Cols  = 3
	fpEq2Cols  = 2
	fpTotalBit = 254

	vecSlabChunk = 1 << 16
)

var (
	bn254P           = new(big.Int).Set(fp.Modulus())
	bn254PMinus1     = new(big.Int).Sub(fp.Modulus(), big.NewInt(1))
	bn254MaxUint254  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), fpTotalBit), big.NewInt(1))
	bn254Q           = new(big.Int).Set(fr.Modulus())
	bn254HalfQ       = new(big.Int).Rsh(fr.Modulus(), 1)
	bn254B           = new(big.Int).Lsh(big.NewInt(1), fpLimbBits)
	bn254LimbMask    = new(big.Int).Sub(bn254B, big.NewInt(1))
	bn254TopLimbMax  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), fpTotalBit-(fpLimbs-1)*fpLimbBits), big.NewInt(1))
	bn254B2          = new(big.Int).Lsh(big.NewInt(1), fpEq2Cols*fpLimbBits)
	bn254B3          = new(big.Int).Lsh(big.NewInt(1), fpEq1Cols*fpLimbBits)
	bn254B5          = new(big.Int).Lsh(big.NewInt(1), fpLimbs*fpLimbBits)
	bn254CRTMax      = new(big.Int).Rsh(new(big.Int).Mul(fr.Modulus(), bn254B5), 1)
	bn254CRTMaxEq1   = new(big.Int).Rsh(new(big.Int).Mul(fr.Modulus(), bn254B3), 1)
	bn254BigZero     = big.NewInt(0)
	bn254BigOne      = big.NewInt(1)
	bn254BigPowB     [fpLimbs]*big.Int
	bn254PLimbs      [fpLimbs]*big.Int
	bn254PLimbsFr    [fpLimbs]fr.Element
	bn254PModQ       fr.Element
	bn254BFr         fr.Element
	bn254B2Fr        fr.Element
	bn254B3Fr        fr.Element
	bn254NegB3Fr     fr.Element
	bn254B5Fr        fr.Element
	bn254PowB        [fpLimbs]fr.Element
	bn254NegPowB     [fpLimbs]fr.Element
	bn254Eq1KScale   [fpEq1Cols]fr.Element
	bn254Eq2KScaleB3 [fpLimbs]fr.Element
	bn254Pow2Fr      [fpLimbs*fpLimbBits + 1]fr.Element
	fpFullOff        = [fpLimbs + 1]int{0, fpLimbBits, 2 * fpLimbBits, 3 * fpLimbBits, 4 * fpLimbBits, fpTotalBit}
	frOne            fr.Element
	frNegOne         fr.Element
	bn254TwistB      [2]*big.Int // b' = 3 / (9 + u) in E2
	bn254VarLimbMax  [fpLimbs]*big.Int
)

// Exact 12x12 F_p matrices for E12 Frobenius maps and E12 bilinear multiplication,
// extracted directly from gnark-crypto/ecc/bn254 at init time (zero hand-typed tables).
var (
	e12Frob1Mat [12][12]*big.Int
	e12Frob2Mat [12][12]*big.Int
	e12Frob3Mat [12][12]*big.Int
	// e12MulCoeffs[outCoord][i][j] is the small integer multiplier for a[i]*b[j] in (a*b)[outCoord].
	e12MulCoeffs [12][12][12]int64
	// g2PhiMat / g2PsiMat / g2NegPsi3XMat: exact F_p 2x2 matrices for E2 Frobenius maps used in final Miller lines
	// and the in-BQS G2[r] prime-order subgroup check ([6x+2]Q + psi(Q) - psi^2(Q) == -psi^3(Q)).
	g2PhiXMat     [2][2]*big.Int
	g2PhiYMat     [2][2]*big.Int
	g2PsiXMat     [2][2]*big.Int
	g2PsiYMat     [2][2]*big.Int
	g2NegPsi3XMat [2][2]*big.Int
)

func init() {
	frOne.SetOne()
	frNegOne.SetInt64(-1)

	// Compile-time cryptographic invariants on BN254:
	// 1. gcd(2^270, q) = 1 for CRT(2^270, q).
	if new(big.Int).GCD(nil, nil, bn254B5, bn254Q).Cmp(bn254BigOne) != 0 {
		panic("bqs fp init: gcd(2^270, q) != 1")
	}
	// 2. Legendre(3 | p) = -1 => y^2 = 3 has no solution in F_p, so every point on E(F_p): y^2 = x^3 + 3 has x != 0.
	if big.Jacobi(big.NewInt(3), bn254P) != -1 {
		panic("bqs fp init: expected 3 to be a quadratic non-residue mod p")
	}
	// 3. (-3)^((p-1)/3) != 1 mod p => x^3 = -3 has no solution in F_p, so every point on E(F_p) has y != 0.
	exp3 := new(big.Int).Div(bn254PMinus1, big.NewInt(3))
	neg3 := new(big.Int).Sub(bn254P, big.NewInt(3))
	if new(big.Int).Exp(neg3, exp3, bn254P).Cmp(bn254BigOne) == 0 {
		panic("bqs fp init: expected -3 to be a cubic non-residue mod p")
	}
	// 4. Exact BN254 G2[r] prime-order subgroup endomorphism soundness assertion:
	// On the sextic twist E'(F_{p^2}), #E'(F_{p^2}) = r * h2 where h2 = 2p - r is odd (ruling out y == 0
	// on E'(F_{p^2})), and Frobenius psi satisfies psi^2 - t*psi + p = 0 (t = p + 1 - r) on ALL of E'(F_{p^2}).
	// For Phi_Ate(psi) = (6x+2) + psi - psi^2 + psi^3 reduced mod (psi^2 - t*psi + p) to a + b*psi,
	// asserting gcd(Norm(Phi_Ate), #E'(F_{p^2})) == r proves Phi_Ate(Q) == O <=> Q in G2[r].
	{
		tTrace := new(big.Int).Add(bn254P, bn254BigOne)
		tTrace.Sub(tTrace, bn254Q)
		h2 := new(big.Int).Sub(new(big.Int).Lsh(bn254P, 1), bn254Q)
		orderE2 := new(big.Int).Mul(bn254Q, h2)
		if orderE2.Bit(0) != 1 {
			panic("bqs fp init: expected #E'(F_{p^2}) to be odd")
		}
		sixX2 := big.NewInt(int64(bn254.LoopCounter[len(bn254.LoopCounter)-1]))
		pModR := new(big.Int).Mod(bn254P, bn254Q)
		negOneModR := new(big.Int).Sub(bn254Q, bn254BigOne)
		for i := len(bn254.LoopCounter) - 2; i >= 0; i-- {
			bit := bn254.LoopCounter[i]
			if bit != 0 {
				m := new(big.Int).Mod(sixX2, bn254Q)
				if m.Cmp(bn254BigOne) == 0 || m.Cmp(negOneModR) == 0 {
					panic("bqs fp init: unexpected Miller loop chord exception mod r")
				}
			}
			sixX2.Lsh(sixX2, 1)
			sixX2.Add(sixX2, big.NewInt(int64(bit)))
		}
		// Phi_Ate(psi) = sixX2 + psi - (t*psi - p) + ((t^2 - p)*psi - t*p)
		//              = (sixX2 + p - t*p) + (1 - t + t^2 - p)*psi
		t2 := new(big.Int).Mul(tTrace, tTrace)
		a := new(big.Int).Add(sixX2, bn254P)
		a.Sub(a, new(big.Int).Mul(tTrace, bn254P))
		bCoef := new(big.Int).Sub(bn254BigOne, tTrace)
		bCoef.Add(bCoef, t2)
		bCoef.Sub(bCoef, bn254P)
		norm := new(big.Int).Mul(a, a)
		norm.Add(norm, new(big.Int).Mul(new(big.Int).Mul(a, bCoef), tTrace))
		norm.Add(norm, new(big.Int).Mul(new(big.Int).Mul(bCoef, bCoef), bn254P))
		if new(big.Int).GCD(nil, nil, norm, orderE2).Cmp(bn254Q) != 0 {
			panic("bqs fp init: gcd(Norm(Phi_Ate), #E'(F_{p^2})) != r")
		}
		// Verify Frobenius chord steps have zero exceptional cases for all Q in G2[r] \ {O}.
		accModR := new(big.Int).Mod(sixX2, bn254Q)
		negPModR := new(big.Int).Sub(bn254Q, pModR)
		if accModR.Cmp(pModR) == 0 || accModR.Cmp(negPModR) == 0 {
			panic("bqs fp init: unexpected Frobenius step 1 chord exception mod r")
		}
		acc1 := new(big.Int).Mod(new(big.Int).Add(accModR, pModR), bn254Q)
		p2ModR := new(big.Int).Mod(new(big.Int).Mul(pModR, pModR), bn254Q)
		negP2ModR := new(big.Int).Sub(bn254Q, p2ModR)
		if acc1.Cmp(p2ModR) == 0 || acc1.Cmp(negP2ModR) == 0 {
			panic("bqs fp init: unexpected Frobenius step 2 chord exception mod r")
		}
	}

	var pow2, two fr.Element
	pow2.SetOne()
	two.SetUint64(2)
	for bit := range bn254Pow2Fr {
		bn254Pow2Fr[bit] = pow2
		pow2.Mul(&pow2, &two)
	}

	for i := 0; i < fpLimbs; i++ {
		bn254BigPowB[i] = new(big.Int).Lsh(bn254BigOne, uint(i*fpLimbBits))
		bn254PLimbs[i] = new(big.Int).And(new(big.Int).Rsh(bn254P, uint(i*fpLimbBits)), bn254LimbMask)
		bn254PLimbsFr[i].SetBigInt(bn254PLimbs[i])
		bn254PowB[i].SetBigInt(bn254BigPowB[i])
		bn254NegPowB[i].Neg(&bn254PowB[i])
		if i < fpLimbs-1 {
			bn254VarLimbMax[i] = new(big.Int).Set(bn254LimbMask)
		} else {
			bn254VarLimbMax[i] = new(big.Int).Set(bn254TopLimbMax)
		}
	}
	bn254PModQ.SetBigInt(new(big.Int).Mod(bn254P, bn254Q))
	bn254BFr.SetBigInt(bn254B)
	bn254B2Fr.SetBigInt(bn254B2)
	bn254B3Fr.SetBigInt(bn254B3)
	bn254NegB3Fr.Neg(&bn254B3Fr)
	bn254B5Fr.SetBigInt(bn254B5)

	// Precompute scalar multipliers for kLimbs[i] in Eq 1 and B^3-scaled Eq 2 RHS (+kPos * p).
	for i := 0; i < fpEq1Cols; i++ {
		var acc, term fr.Element
		for col := i; col < fpEq1Cols; col++ {
			term.Mul(&bn254PowB[col], &bn254PLimbsFr[col-i])
			acc.Add(&acc, &term)
		}
		bn254Eq1KScale[i] = acc
	}
	for i := 0; i < fpLimbs; i++ {
		var acc, term fr.Element
		for col := max(fpEq1Cols, i); col < fpLimbs; col++ {
			term.Mul(&bn254PowB[col], &bn254PLimbsFr[col-i])
			acc.Add(&acc, &term)
		}
		bn254Eq2KScaleB3[i] = acc
	}

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
		setE12Coord(&basis, col, bn254BigOne)
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
		setE12Coord(&ei, i, bn254BigOne)
		for j := 0; j < 12; j++ {
			var ej, prod bn254.E12
			setE12Coord(&ej, j, bn254BigOne)
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

	// Extract exact G2 Frobenius Q1 = psi(Q), Q2 = -psi^2(Q), and Q3 = -psi^3(Q) = psi(Q2) 2x2 matrices over F_p.
	for col := 0; col < 2; col++ {
		var e bn254.E2
		if col == 0 {
			e.A0.SetOne()
		} else {
			e.A1.SetOne()
		}
		var px, py, sx, sy, q3x, q3y bn254.E2
		px.Conjugate(&e).MulByNonResidue1Power2(&px)
		py.Conjugate(&e).MulByNonResidue1Power3(&py)
		sx.MulByNonResidue2Power2(&e)
		sy.MulByNonResidue2Power3(&e).Neg(&sy)
		q3x.Conjugate(&sx).MulByNonResidue1Power2(&q3x)
		q3y.Conjugate(&sy).MulByNonResidue1Power3(&q3y)
		if !q3y.Equal(&py) {
			panic("bqs fp init: expected (-psi^3(Q)).Y == psi(Q).Y")
		}

		g2PhiXMat[0][col] = px.A0.BigInt(new(big.Int))
		g2PhiXMat[1][col] = px.A1.BigInt(new(big.Int))
		g2PhiYMat[0][col] = py.A0.BigInt(new(big.Int))
		g2PhiYMat[1][col] = py.A1.BigInt(new(big.Int))
		g2PsiXMat[0][col] = sx.A0.BigInt(new(big.Int))
		g2PsiXMat[1][col] = sx.A1.BigInt(new(big.Int))
		g2PsiYMat[0][col] = sy.A0.BigInt(new(big.Int))
		g2PsiYMat[1][col] = sy.A1.BigInt(new(big.Int))
		g2NegPsi3XMat[0][col] = q3x.A0.BigInt(new(big.Int))
		g2NegPsi3XMat[1][col] = q3x.A1.BigInt(new(big.Int))
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

func splitValLimbs(v *big.Int) [fpLimbs]*big.Int {
	var outL [fpLimbs]*big.Int
	for i := 0; i < fpLimbs; i++ {
		lv := new(big.Int).Rsh(v, uint(i*fpLimbBits))
		if i < fpLimbs-1 {
			lv.And(lv, bn254LimbMask)
		}
		outL[i] = lv
	}
	return outL
}

// FpVar represents a non-native BN254 F_p element inside a BQS over F_q.
type FpVar struct {
	Limbs      [fpLimbs]Vec
	Full       Vec
	Val        *big.Int // witness value in [0, p-1] (nil during compile-only mode)
	Const      bool
	ConstLimbs [fpLimbs]*big.Int
	valLimbs   [fpLimbs]*big.Int // cached witness limbs when synth=true
	id         int               // unique positive ID for allocated variables (0 for constants)
}

// FpExpr represents a deferred (zero-constraint) linear combination of FpVars plus an optional constant.
type FpExpr struct {
	Terms []FpLinTerm
	Const *big.Int // reduced in [0, p-1], or nil if zero
}

// E2Var represents an element of BN254 F_{p^2} = F_p[u]/(u^2+1).
type E2Var struct {
	A0, A1 FpVar
}

// E12Var represents an element of BN254 F_{p^{12}} as 12 F_p coordinates in gnark-crypto tower order.
type E12Var struct {
	C [12]FpVar
}

// E12Expr represents an E12 element whose coordinates may be deferred FpExpr linear combinations.
type E12Expr struct {
	C [12]FpExpr
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

func fpExprVar(v FpVar) FpExpr {
	if v.Const {
		if v.Val == nil || v.Val.Sign() == 0 {
			return FpExpr{}
		}
		return FpExpr{Const: new(big.Int).Set(v.Val)}
	}
	return FpExpr{Terms: []FpLinTerm{{Coeff: 1, X: v}}}
}

func fpExprNegVar(v FpVar) FpExpr {
	if v.Const {
		if v.Val == nil || v.Val.Sign() == 0 {
			return FpExpr{}
		}
		return FpExpr{Const: new(big.Int).Sub(bn254P, v.Val)}
	}
	return FpExpr{Terms: []FpLinTerm{{Coeff: -1, X: v}}}
}

func fpExprConst(c *big.Int) FpExpr {
	if c == nil || c.Sign() == 0 {
		return FpExpr{}
	}
	m := new(big.Int).Mod(c, bn254P)
	if m.Sign() == 0 {
		return FpExpr{}
	}
	return FpExpr{Const: m}
}

func fpExprVarPlusConst(v FpVar, c *big.Int) FpExpr {
	e := fpExprVar(v)
	if c == nil || c.Sign() == 0 {
		return e
	}
	m := new(big.Int).Mod(c, bn254P)
	if m.Sign() == 0 {
		return e
	}
	if e.Const == nil {
		e.Const = m
	} else {
		e.Const = new(big.Int).Add(e.Const, m)
		e.Const.Mod(e.Const, bn254P)
		if e.Const.Sign() == 0 {
			e.Const = nil
		}
	}
	return e
}

func fpExprSum2(a, b FpVar) FpExpr {
	if a.Const && b.Const {
		return fpExprConst(new(big.Int).Add(a.Val, b.Val))
	}
	if a.Const {
		return fpExprVarPlusConst(b, a.Val)
	}
	if b.Const {
		return fpExprVarPlusConst(a, b.Val)
	}
	return FpExpr{Terms: []FpLinTerm{{Coeff: 1, X: a}, {Coeff: 1, X: b}}}
}

func e12ToExpr(e E12Var) E12Expr {
	var out E12Expr
	for i := 0; i < 12; i++ {
		out.C[i] = fpExprVar(e.C[i])
	}
	return out
}

func (e FpExpr) evalModP() *big.Int {
	acc := new(big.Int)
	if e.Const != nil {
		acc.Set(e.Const)
	}
	for _, t := range e.Terms {
		term := new(big.Int).Mul(t.X.Val, big.NewInt(t.Coeff))
		acc.Add(acc, term)
	}
	acc.Mod(acc, bn254P)
	return acc
}

// FpBuilder incrementally constructs a bqs.System and (when synth=true) the exact
// Boolean witness vector w []bool in lockstep.
type FpBuilder struct {
	N           int
	Constraints []Constraint
	synth       bool
	W           []bool // length N+1, W[0] = true when synth=true

	zeroFp FpVar
	oneFp  FpVar

	// Chunked slab for immutable Vec allocations (eliminates small per-Vec heap churn).
	slab []Term

	// Generation-stamped O(nnz) sparse linear-form accumulator (zero per-constraint map allocations).
	accGen  uint32
	accSeen []uint32
	accPos  []int
	accBuf  Vec
}

// NewFpBuilder creates a BQS builder. If synth is true, it records exact Boolean witness bits.
func NewFpBuilder(synth bool) *FpBuilder {
	b := &FpBuilder{
		synth:   synth,
		accSeen: make([]uint32, 4096),
		accPos:  make([]int, 4096),
		accBuf:  make(Vec, 0, 1024),
	}
	if synth {
		b.W = make([]bool, 1, 1<<16)
		b.W[0] = true
	}
	b.zeroFp = b.ConstFp(bn254BigZero)
	b.oneFp = b.ConstFp(bn254BigOne)
	return b
}

// allocTermSlice returns a fresh immutable-capped Term slice of length n from the builder slab.
func (b *FpBuilder) allocTermSlice(n int) Vec {
	if n == 0 {
		return nil
	}
	if n > len(b.slab) {
		sz := vecSlabChunk
		if n > sz {
			sz = n
		}
		b.slab = make([]Term, sz)
	}
	out := b.slab[:n:n]
	b.slab = b.slab[n:]
	return out
}

func (b *FpBuilder) accReset() {
	b.accGen++
	if b.accGen == 0 {
		clear(b.accSeen)
		b.accGen = 1
	}
	if b.N >= len(b.accSeen) {
		newLen := len(b.accSeen)
		for newLen <= b.N {
			newLen *= 2
		}
		seen := make([]uint32, newLen)
		copy(seen, b.accSeen)
		b.accSeen = seen
		pos := make([]int, newLen)
		copy(pos, b.accPos)
		b.accPos = pos
	}
	b.accBuf = b.accBuf[:0]
}

func (b *FpBuilder) accAddTerm(idx int, v fr.Element) {
	if v.IsZero() {
		return
	}
	if b.accSeen[idx] == b.accGen {
		p := b.accPos[idx]
		b.accBuf[p].V.Add(&b.accBuf[p].V, &v)
	} else {
		b.accSeen[idx] = b.accGen
		b.accPos[idx] = len(b.accBuf)
		b.accBuf = append(b.accBuf, Term{I: idx, V: v})
	}
}

func (b *FpBuilder) accAddScaled(v Vec, c fr.Element) {
	if len(v) == 0 || c.IsZero() {
		return
	}
	if c.IsOne() {
		for _, t := range v {
			b.accAddTerm(t.I, t.V)
		}
		return
	}
	if c.Equal(&frNegOne) {
		var nv fr.Element
		for _, t := range v {
			nv.Neg(&t.V)
			b.accAddTerm(t.I, nv)
		}
		return
	}
	var sv fr.Element
	for _, t := range v {
		sv.Mul(&t.V, &c)
		b.accAddTerm(t.I, sv)
	}
}

func (b *FpBuilder) accFinish() Vec {
	n := len(b.accBuf)
	if n == 0 {
		return nil
	}
	nnz := 0
	for i := range b.accBuf {
		if !b.accBuf[i].V.IsZero() {
			nnz++
		}
	}
	if nnz == 0 {
		return nil
	}
	out := b.allocTermSlice(nnz)
	if nnz == n {
		copy(out, b.accBuf)
		return out
	}
	k := 0
	for i := range b.accBuf {
		if !b.accBuf[i].V.IsZero() {
			out[k] = b.accBuf[i]
			k++
		}
	}
	return out
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
		if b.synth && val != nil && val.Sign() != 0 {
			panic(fmt.Sprintf("bqs fp allocBits: non-zero value %v for 0 bits", val))
		}
		return nil
	}
	if b.synth && (val == nil || val.Sign() < 0 || val.BitLen() > nBits) {
		panic(fmt.Sprintf("bqs fp allocBits: value %v does not fit in %d unsigned bits", val, nBits))
	}
	v := b.allocTermSlice(nBits)
	base := b.N
	b.N += nBits
	for i := 0; i < nBits; i++ {
		v[i] = Term{I: base + 1 + i, V: bn254Pow2Fr[i]}
	}
	if b.synth {
		for i := 0; i < nBits; i++ {
			b.W = append(b.W, val.Bit(i) == 1)
		}
	}
	return v
}

// allocLimbs allocates a non-negative integer of totalBits (0 <= totalBits <= fpLimbs*fpLimbBits)
// split into fpLimbs radix-2^54 limbs, returning each limb Vec and the combined full Vec.
func (b *FpBuilder) allocLimbs(totalBits int, val *big.Int) ([fpLimbs]Vec, Vec, [fpLimbs]int) {
	var limbs [fpLimbs]Vec
	var widths [fpLimbs]int
	if totalBits <= 0 {
		if b.synth && val != nil && val.Sign() != 0 {
			panic(fmt.Sprintf("bqs fp allocLimbs: non-zero value %v for 0 bits", val))
		}
		return limbs, nil, widths
	}
	if totalBits > fpLimbs*fpLimbBits {
		panic(fmt.Sprintf("bqs fp allocLimbs: %d bits exceeds %d-bit limb capacity", totalBits, fpLimbs*fpLimbBits))
	}
	if b.synth && (val == nil || val.Sign() < 0 || val.BitLen() > totalBits) {
		panic(fmt.Sprintf("bqs fp allocLimbs: value %v does not fit in %d unsigned bits", val, totalBits))
	}

	full := b.allocTermSlice(totalBits)
	base := b.N
	b.N += totalBits
	bitOff := 0
	for li := 0; li < fpLimbs; li++ {
		rem := totalBits - li*fpLimbBits
		if rem <= 0 {
			continue
		}
		w := min(fpLimbBits, rem)
		widths[li] = w
		lv := b.allocTermSlice(w)
		for i := 0; i < w; i++ {
			idx := base + 1 + bitOff + i
			lv[i] = Term{I: idx, V: bn254Pow2Fr[i]}
			full[bitOff+i] = Term{I: idx, V: bn254Pow2Fr[bitOff+i]}
		}
		limbs[li] = lv
		bitOff += w
	}
	if b.synth {
		for i := 0; i < totalBits; i++ {
			b.W = append(b.W, val.Bit(i) == 1)
		}
	}
	return limbs, full, widths
}

// NewFpVar allocates a 254-bit non-native F_p witness variable.
func (b *FpBuilder) NewFpVar(val *big.Int) FpVar {
	var vMod *big.Int
	var vLimbs [fpLimbs]*big.Int
	if b.synth {
		vMod = new(big.Int).Mod(val, bn254P)
		vLimbs = splitValLimbs(vMod)
	}
	id := b.N + 1
	limbs, full, _ := b.allocLimbs(fpTotalBit, vMod)
	return FpVar{Limbs: limbs, Full: full, Val: vMod, valLimbs: vLimbs, id: id}
}

// ConstFp creates a constant F_p element (0 unknowns).
func (b *FpBuilder) ConstFp(val *big.Int) FpVar {
	v := new(big.Int).Mod(val, bn254P)
	cLimbs := splitValLimbs(v)
	var limbs [fpLimbs]Vec
	for i := 0; i < fpLimbs; i++ {
		if cLimbs[i].Sign() != 0 {
			var fe fr.Element
			fe.SetBigInt(cLimbs[i])
			limbs[i] = Vec{{I: 0, V: fe}}
		}
	}
	var full Vec
	if v.Sign() != 0 {
		var fe fr.Element
		fe.SetBigInt(new(big.Int).Mod(v, bn254Q))
		full = Vec{{I: 0, V: fe}}
	}
	return FpVar{Limbs: limbs, Full: full, Val: v, Const: true, ConstLimbs: cLimbs, valLimbs: cLimbs}
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

func honestMaxValOf(v FpVar) *big.Int {
	if v.Const {
		return v.Val
	}
	return bn254PMinus1
}

func advMaxValOf(v FpVar) *big.Int {
	if v.Const {
		return v.Val
	}
	return bn254MaxUint254
}

func maxLimbOf(v FpVar, li int) *big.Int {
	if v.Const {
		return v.ConstLimbs[li]
	}
	return bn254VarLimbMax[li]
}

type constVarTerm struct {
	coeff int64
	c     FpVar // Const == true, non-zero
	x     FpVar // Const == false
}

type varProdKey struct {
	aID, bID int
}

// AssertQuadModP adds 2 or 3 exact CRT BQS constraints proving over Z:
//
//	sum_m prods[m].Coeff * A_m * B_m + sum_l lins[l].Coeff * X_l + cnst == out (mod p).
//
// Constant * Variable products are lowered to linear terms, duplicate variable pairs
// (including symmetric squares A*B + B*A) are merged, products are factored by the side
// with fewer distinct variables to minimize Fmax, and all CRT / Eq1 / Eq2 overflow
// assertions are verified over adversarial Boolean ranges [0, 2^254-1] and [0, 2^bits-1].
func (b *FpBuilder) AssertQuadModP(prods []FpQuadTerm, lins []FpLinTerm, cnst *big.Int, out FpVar) {
	constAcc := new(big.Int)
	if cnst != nil {
		constAcc.Set(cnst)
	}

	// 1. Canonicalize quadratic terms: fold const*const into constAcc, split const*var from var*var,
	// and merge duplicate (A, B) / (B, A) variable pairs.
	var varProds []FpQuadTerm
	varProdIdx := make(map[varProdKey]int, len(prods))
	var constVarProds []constVarTerm
	for _, pt := range prods {
		if pt.Coeff == 0 {
			continue
		}
		if pt.A.Const && pt.B.Const {
			if pt.A.Val.Sign() != 0 && pt.B.Val.Sign() != 0 {
				t := new(big.Int).Mul(pt.A.Val, pt.B.Val)
				t.Mul(t, big.NewInt(pt.Coeff))
				constAcc.Add(constAcc, t)
			}
			continue
		}
		if pt.A.Const {
			if pt.A.Val.Sign() == 0 {
				continue
			}
			constVarProds = append(constVarProds, constVarTerm{coeff: pt.Coeff, c: pt.A, x: pt.B})
			continue
		}
		if pt.B.Const {
			if pt.B.Val.Sign() == 0 {
				continue
			}
			constVarProds = append(constVarProds, constVarTerm{coeff: pt.Coeff, c: pt.B, x: pt.A})
			continue
		}
		a, bv := pt.A, pt.B
		if a.id > bv.id {
			a, bv = bv, a
		}
		key := varProdKey{a.id, bv.id}
		if idx, ok := varProdIdx[key]; ok {
			varProds[idx].Coeff += pt.Coeff
		} else {
			varProdIdx[key] = len(varProds)
			varProds = append(varProds, FpQuadTerm{Coeff: pt.Coeff, A: a, B: bv})
		}
	}
	// Compact out any varProds whose merged coefficient cancelled to 0.
	{
		n := 0
		for _, pt := range varProds {
			if pt.Coeff != 0 {
				varProds[n] = pt
				n++
			}
		}
		varProds = varProds[:n]
	}

	// 2. Canonicalize linear terms (absorbing -out directly into lins / constAcc) and merge duplicate vars.
	var activeLins []FpLinTerm
	linIdx := make(map[int]int, len(lins)+1)
	addLin := func(coeff int64, x FpVar) {
		if coeff == 0 {
			return
		}
		if x.Const {
			if x.Val.Sign() != 0 {
				t := new(big.Int).Mul(x.Val, big.NewInt(coeff))
				constAcc.Add(constAcc, t)
			}
			return
		}
		if idx, ok := linIdx[x.id]; ok {
			activeLins[idx].Coeff += coeff
		} else {
			linIdx[x.id] = len(activeLins)
			activeLins = append(activeLins, FpLinTerm{Coeff: coeff, X: x})
		}
	}
	for _, lt := range lins {
		addLin(lt.Coeff, lt.X)
	}
	addLin(-1, out)
	{
		n := 0
		for _, lt := range activeLins {
			if lt.Coeff != 0 {
				activeLins[n] = lt
				n++
			}
		}
		activeLins = activeLins[:n]
	}

	// 3. Compute exact honest bounds (for tight K sizing) and adversarial bounds (for compile-time CRT proof).
	honPos, honNeg := new(big.Int), new(big.Int)
	advPos, advNeg := new(big.Int), new(big.Int)
	if constAcc.Sign() >= 0 {
		honPos.Add(honPos, constAcc)
		advPos.Add(advPos, constAcc)
	} else {
		honNeg.Sub(honNeg, constAcc)
		advNeg.Sub(advNeg, constAcc)
	}
	addSignedBound := func(coeff int64, hUB, aUB *big.Int) {
		if coeff > 0 {
			cBig := big.NewInt(coeff)
			honPos.Add(honPos, new(big.Int).Mul(hUB, cBig))
			advPos.Add(advPos, new(big.Int).Mul(aUB, cBig))
		} else {
			cBig := big.NewInt(-coeff)
			honNeg.Add(honNeg, new(big.Int).Mul(hUB, cBig))
			advNeg.Add(advNeg, new(big.Int).Mul(aUB, cBig))
		}
	}
	for _, pt := range varProds {
		hUB := new(big.Int).Mul(honestMaxValOf(pt.A), honestMaxValOf(pt.B))
		aUB := new(big.Int).Mul(advMaxValOf(pt.A), advMaxValOf(pt.B))
		addSignedBound(pt.Coeff, hUB, aUB)
	}
	for _, cv := range constVarProds {
		hUB := new(big.Int).Mul(cv.c.Val, honestMaxValOf(cv.x))
		aUB := new(big.Int).Mul(cv.c.Val, advMaxValOf(cv.x))
		addSignedBound(cv.coeff, hUB, aUB)
	}
	for _, lt := range activeLins {
		addSignedBound(lt.Coeff, honestMaxValOf(lt.X), advMaxValOf(lt.X))
	}

	// Exact honest range for K = (sum - out) / p in [-kBias, kMax]:
	// -honNeg <= K*p <= honPos  ==>  -floor(honNeg/p) <= K <= floor(honPos/p).
	kBias := new(big.Int).Quo(honNeg, bn254P)
	kMax := new(big.Int).Quo(honPos, bn254P)
	kRange := new(big.Int).Add(kMax, kBias)
	kBits := kRange.BitLen()
	if kBits > fpLimbs*fpLimbBits {
		panic(fmt.Sprintf("bqs AssertQuadModP: quotient kBits (%d) exceeds limb capacity %d", kBits, fpLimbs*fpLimbBits))
	}

	// Verify exact adversarial CRT soundness bound over ALL Boolean assignments:
	//   E = sum - out - (kPos - kBias) * p, with kPos in [0, 2^kBits - 1].
	kPosMax := new(big.Int)
	if kBits > 0 {
		kPosMax.Sub(new(big.Int).Lsh(bn254BigOne, uint(kBits)), bn254BigOne)
	}
	kAdvMax := new(big.Int).Sub(kPosMax, kBias)
	advEPos := new(big.Int).Add(advPos, new(big.Int).Mul(kBias, bn254P))
	advENeg := new(big.Int).Set(advNeg)
	if kAdvMax.Sign() > 0 {
		advENeg.Add(advENeg, new(big.Int).Mul(kAdvMax, bn254P))
	}
	maxE := advEPos
	if advENeg.Cmp(maxE) > 0 {
		maxE = advENeg
	}
	useTwoEq := maxE.Cmp(bn254CRTMaxEq1) < 0
	if !useTwoEq && maxE.Cmp(bn254CRTMax) >= 0 {
		panic(fmt.Sprintf("bqs AssertQuadModP: adversarial |E| bound (%d bits) exceeds CRT modulus q*2^270/2", maxE.BitLen()))
	}
	activeCols := fpLimbs
	if useTwoEq {
		activeCols = fpEq1Cols
	}

	// 4. Synthesize exact witness quotient kPos = K + kBias.
	var kPosVal *big.Int
	var sumCols [fpLimbs]*big.Int
	if b.synth {
		exactSum := new(big.Int).Set(constAcc)
		for _, pt := range varProds {
			t := new(big.Int).Mul(pt.A.Val, pt.B.Val)
			t.Mul(t, big.NewInt(pt.Coeff))
			exactSum.Add(exactSum, t)
		}
		for _, cv := range constVarProds {
			t := new(big.Int).Mul(cv.c.Val, cv.x.Val)
			t.Mul(t, big.NewInt(cv.coeff))
			exactSum.Add(exactSum, t)
		}
		for _, lt := range activeLins {
			t := new(big.Int).Mul(lt.X.Val, big.NewInt(lt.Coeff))
			exactSum.Add(exactSum, t)
		}
		kVal, rem := new(big.Int).QuoRem(exactSum, bn254P, new(big.Int))
		if rem.Sign() != 0 {
			panic(fmt.Sprintf("bqs AssertQuadModP: witness does not satisfy equation mod p (rem=%v)", rem))
		}
		kPosVal = new(big.Int).Add(kVal, kBias)
		if kPosVal.Sign() < 0 || kPosVal.BitLen() > kBits {
			panic(fmt.Sprintf("bqs AssertQuadModP: kPos out of range (%d > %d bits)", kPosVal.BitLen(), kBits))
		}
		for c := 0; c < activeCols; c++ {
			sumCols[c] = new(big.Int)
		}
	}
	kLimbs, kFull, kWidths := b.allocLimbs(kBits, kPosVal)

	// Absorb +kBias * p into constAcc so E = sum - out - kPos*p + adjConst = 0.
	adjConst := new(big.Int).Add(constAcc, new(big.Int).Mul(kBias, bn254P))
	var adjConstLimbs [fpLimbs]*big.Int
	{
		cur := new(big.Int).Set(adjConst)
		for c := 0; c < activeCols; c++ {
			qDiv, rMod := new(big.Int).QuoRem(cur, bn254B, new(big.Int))
			if rMod.Sign() < 0 {
				rMod.Add(rMod, bn254B)
				qDiv.Sub(qDiv, bn254BigOne)
			}
			adjConstLimbs[c] = rMod
			cur = qDiv
		}
	}

	// 5. Compute tight directional column bounds colPos[c], colNeg[c] (over all Boolean assignments)
	// and exact witness column sums sumCols[c].
	var colPos, colNeg [fpLimbs]*big.Int
	for c := 0; c < activeCols; c++ {
		colPos[c] = new(big.Int).Set(adjConstLimbs[c])
		colNeg[c] = new(big.Int)
		if b.synth {
			sumCols[c].Add(sumCols[c], adjConstLimbs[c])
		}
	}

	var kMaxLimb [fpLimbs]*big.Int
	for li := 0; li < fpLimbs; li++ {
		if kWidths[li] > 0 {
			kMaxLimb[li] = new(big.Int).Sub(new(big.Int).Lsh(bn254BigOne, uint(kWidths[li])), bn254BigOne)
		} else {
			kMaxLimb[li] = bn254BigZero
		}
	}

	// 5a. Variable * Variable products.
	for _, pt := range varProds {
		cAbs := pt.Coeff
		pos := cAbs > 0
		if !pos {
			cAbs = -cAbs
		}
		cAbsBig := big.NewInt(cAbs)
		var cBig *big.Int
		if b.synth {
			cBig = big.NewInt(pt.Coeff)
		}
		for col := 0; col < activeCols; col++ {
			for i := 0; i <= col; i++ {
				j := col - i
				if len(pt.A.Limbs[i]) == 0 || len(pt.B.Limbs[j]) == 0 {
					continue
				}
				ub := new(big.Int).Mul(maxLimbOf(pt.A, i), maxLimbOf(pt.B, j))
				ub.Mul(ub, cAbsBig)
				if pos {
					colPos[col].Add(colPos[col], ub)
				} else {
					colNeg[col].Add(colNeg[col], ub)
				}
				if b.synth {
					t := new(big.Int).Mul(pt.A.valLimbs[i], pt.B.valLimbs[j])
					t.Mul(t, cBig)
					sumCols[col].Add(sumCols[col], t)
				}
			}
		}
	}

	// 5b. Constant * Variable products (linear in constraints!).
	for _, cv := range constVarProds {
		cAbs := cv.coeff
		pos := cAbs > 0
		if !pos {
			cAbs = -cAbs
		}
		cAbsBig := big.NewInt(cAbs)
		var cBig *big.Int
		if b.synth {
			cBig = big.NewInt(cv.coeff)
		}
		for col := 0; col < activeCols; col++ {
			for i := 0; i <= col; i++ {
				j := col - i
				if cv.c.ConstLimbs[i].Sign() == 0 || len(cv.x.Limbs[j]) == 0 {
					continue
				}
				ub := new(big.Int).Mul(cv.c.ConstLimbs[i], maxLimbOf(cv.x, j))
				ub.Mul(ub, cAbsBig)
				if pos {
					colPos[col].Add(colPos[col], ub)
				} else {
					colNeg[col].Add(colNeg[col], ub)
				}
				if b.synth {
					t := new(big.Int).Mul(cv.c.ConstLimbs[i], cv.x.valLimbs[j])
					t.Mul(t, cBig)
					sumCols[col].Add(sumCols[col], t)
				}
			}
		}
	}

	// 5c. Linear terms (including -out).
	for _, lt := range activeLins {
		cAbs := lt.Coeff
		pos := cAbs > 0
		if !pos {
			cAbs = -cAbs
		}
		cAbsBig := big.NewInt(cAbs)
		var cBig *big.Int
		if b.synth {
			cBig = big.NewInt(lt.Coeff)
		}
		for col := 0; col < activeCols; col++ {
			if len(lt.X.Limbs[col]) == 0 {
				continue
			}
			ub := new(big.Int).Mul(maxLimbOf(lt.X, col), cAbsBig)
			if pos {
				colPos[col].Add(colPos[col], ub)
			} else {
				colNeg[col].Add(colNeg[col], ub)
			}
			if b.synth {
				t := new(big.Int).Mul(lt.X.valLimbs[col], cBig)
				sumCols[col].Add(sumCols[col], t)
			}
		}
	}

	// 5d. Subtract kPos * p across activeCols (always contributes to colNeg).
	var kL [fpLimbs]*big.Int
	if b.synth {
		kL = splitValLimbs(kPosVal)
	}
	for col := 0; col < activeCols; col++ {
		for i := 0; i <= col; i++ {
			j := col - i
			if kWidths[i] == 0 || bn254PLimbs[j].Sign() == 0 {
				continue
			}
			ub := new(big.Int).Mul(kMaxLimb[i], bn254PLimbs[j])
			colNeg[col].Add(colNeg[col], ub)
			if b.synth {
				t := new(big.Int).Mul(kL[i], bn254PLimbs[j])
				sumCols[col].Sub(sumCols[col], t)
			}
		}
	}

	// 6. Group varProds by whichever operand side (A or B) has fewer distinct variables
	// and materialize each group's right-hand linear combination Y ONCE in limb-major order.
	// Every product in Eq 1, B^3-scaled Eq 2, and Eq 3 is then a zero-copy subslice of u.Full and Y!
	type factorItem struct {
		coeff int64
		other FpVar
	}
	type factorGroup struct {
		left  FpVar
		items []factorItem
		yVec  Vec
		yOff  [fpLimbs + 1]int
	}
	var groups []factorGroup
	if len(varProds) > 0 {
		leftSet := make(map[int]struct{}, len(varProds))
		rightSet := make(map[int]struct{}, len(varProds))
		for _, pt := range varProds {
			leftSet[pt.A.id] = struct{}{}
			rightSet[pt.B.id] = struct{}{}
		}
		swapSide := len(rightSet) < len(leftSet)
		groupIdx := make(map[int]int, min(len(leftSet), len(rightSet)))
		for _, pt := range varProds {
			lVar, rVar := pt.A, pt.B
			if swapSide {
				lVar, rVar = rVar, lVar
			}
			gi, ok := groupIdx[lVar.id]
			if !ok {
				gi = len(groups)
				groupIdx[lVar.id] = gi
				groups = append(groups, factorGroup{left: lVar})
			}
			groups[gi].items = append(groups[gi].items, factorItem{coeff: pt.Coeff, other: rVar})
		}

		// Build limb-major Y once per group (all items in a group have distinct other.id!).
		for gi := range groups {
			g := &groups[gi]
			if len(g.items) == 1 && g.items[0].coeff == 1 {
				g.yVec = g.items[0].other.Full
				g.yOff = fpFullOff
				continue
			}
			kCount := len(g.items)
			for li := 0; li < fpLimbs; li++ {
				g.yOff[li+1] = g.yOff[li] + kCount*(fpFullOff[li+1]-fpFullOff[li])
			}
			yVec := b.allocTermSlice(g.yOff[fpLimbs])
			for li := 0; li < fpLimbs; li++ {
				lo, hi := fpFullOff[li], fpFullOff[li+1]
				w := hi - lo
				pos := g.yOff[li]
				for _, it := range g.items {
					src := it.other.Full[lo:hi]
					dst := yVec[pos : pos+w]
					switch it.coeff {
					case 1:
						copy(dst, src)
					case -1:
						for k := range src {
							dst[k].I = src[k].I
							dst[k].V.Neg(&src[k].V)
						}
					case 2:
						for k := range src {
							dst[k].I = src[k].I
							dst[k].V.Double(&src[k].V)
						}
					case -2:
						for k := range src {
							dst[k].I = src[k].I
							dst[k].V.Double(&src[k].V)
							dst[k].V.Neg(&dst[k].V)
						}
					default:
						cFr := frInt64(it.coeff)
						for k := range src {
							dst[k].I = src[k].I
							dst[k].V.Mul(&src[k].V, &cFr)
						}
					}
					pos += w
				}
			}
			g.yVec = yVec
		}
	}

	// 7. Eq 1 (mod 2^162): S0 + B*S1 + B^2*S2 = B^3 * t1.
	eq1MaxPos := new(big.Int).Set(colPos[0])
	eq1MaxNeg := new(big.Int).Set(colNeg[0])
	for c := 1; c < fpEq1Cols; c++ {
		eq1MaxPos.Add(eq1MaxPos, new(big.Int).Mul(bn254BigPowB[c], colPos[c]))
		eq1MaxNeg.Add(eq1MaxNeg, new(big.Int).Mul(bn254BigPowB[c], colNeg[c]))
	}
	t1Bias := new(big.Int).Quo(eq1MaxNeg, bn254B3)
	t1Max := new(big.Int).Quo(eq1MaxPos, bn254B3)
	t1Range := new(big.Int).Add(t1Max, t1Bias)
	t1Bits := t1Range.BitLen()
	t1PosMax := new(big.Int)
	if t1Bits > 0 {
		t1PosMax.Sub(new(big.Int).Lsh(bn254BigOne, uint(t1Bits)), bn254BigOne)
	}
	t1AdvMax := new(big.Int).Sub(t1PosMax, t1Bias)
	// Adversarial soundness assertion: |lhs1 - B^3*(t1Pos - t1Bias)| < q/2.
	eq1AdvPos := new(big.Int).Add(eq1MaxPos, new(big.Int).Mul(bn254B3, t1Bias))
	eq1AdvNeg := new(big.Int).Set(eq1MaxNeg)
	if t1AdvMax.Sign() > 0 {
		eq1AdvNeg.Add(eq1AdvNeg, new(big.Int).Mul(bn254B3, t1AdvMax))
	}
	if eq1AdvPos.Cmp(bn254HalfQ) >= 0 || eq1AdvNeg.Cmp(bn254HalfQ) >= 0 {
		panic(fmt.Sprintf("bqs AssertQuadModP: Eq1 adversarial bound (%d, %d bits) exceeds q/2",
			eq1AdvPos.BitLen(), eq1AdvNeg.BitLen()))
	}

	var t1Val, t1PosVal *big.Int
	if b.synth {
		lhs1 := new(big.Int).Set(sumCols[0])
		for c := 1; c < fpEq1Cols; c++ {
			lhs1.Add(lhs1, new(big.Int).Mul(bn254BigPowB[c], sumCols[c]))
		}
		var rem *big.Int
		t1Val, rem = new(big.Int).QuoRem(lhs1, bn254B3, new(big.Int))
		if rem.Sign() != 0 {
			panic(fmt.Sprintf("bqs AssertQuadModP: Eq1 not divisible by 2^162 (rem=%v)", rem))
		}
		t1PosVal = new(big.Int).Add(t1Val, t1Bias)
	}
	t1PosVec := b.allocBits(t1Bits, t1PosVal)

	// Emit zero-copy factored Eq 1 products: (B^a * u_a) * (sum_{b=0}^{2-a} B^b * Y_b).
	var eq1Prods []Product
	if len(groups) > 0 {
		eq1Prods = make([]Product, 0, len(groups)*fpEq1Cols)
		for gi := range groups {
			g := &groups[gi]
			for a := 0; a < fpEq1Cols; a++ {
				eq1Prods = append(eq1Prods, Product{
					A: g.left.Full[fpFullOff[a]:fpFullOff[a+1]],
					B: g.yVec[g.yOff[0]:g.yOff[fpEq1Cols-a]],
				})
			}
		}
	}
	// Emit Eq 1 RHS: B^3*(t1Pos - t1Bias) - (adjConst + constVar + activeLins) + kPos*p (cols 0..2).
	b.accReset()
	b.accAddScaled(t1PosVec, bn254B3Fr)
	{
		c0 := new(big.Int).Mul(t1Bias, bn254B3)
		c0.Neg(c0)
		for c := 0; c < fpEq1Cols; c++ {
			if adjConstLimbs[c].Sign() != 0 {
				c0.Sub(c0, new(big.Int).Mul(bn254BigPowB[c], adjConstLimbs[c]))
			}
		}
		b.accAddTerm(0, frBig(c0))
	}
	for _, cv := range constVarProds {
		cFr := frInt64(cv.coeff)
		for j := 0; j < fpEq1Cols; j++ {
			if len(cv.x.Limbs[j]) == 0 {
				continue
			}
			var acc, term fr.Element
			for col := j; col < fpEq1Cols; col++ {
				i := col - j
				if len(cv.c.Limbs[i]) == 0 {
					continue
				}
				term.Mul(&bn254NegPowB[col], &cv.c.Limbs[i][0].V)
				acc.Add(&acc, &term)
			}
			if !acc.IsZero() {
				acc.Mul(&acc, &cFr)
				b.accAddScaled(cv.x.Limbs[j], acc)
			}
		}
	}
	for _, lt := range activeLins {
		b.accAddScaled(lt.X.Full[:fpFullOff[fpEq1Cols]], frInt64(-lt.Coeff))
	}
	for i := 0; i < fpEq1Cols; i++ {
		if len(kLimbs[i]) > 0 {
			b.accAddScaled(kLimbs[i], bn254Eq1KScale[i])
		}
	}
	if len(eq1Prods) == 0 {
		eq1Prods = []Product{{}}
	}
	b.Constraints = append(b.Constraints, Constraint{Products: eq1Prods, C: b.accFinish()})

	// 8. Eq 2 (mod 2^270): B^3 * ((S3 + t1) + B*S4) = B^5 * t2 (skipped when 2-constraint CRT(2^162, q) suffices).
	// Scaling both sides by the unit B^3 in F_q^* preserves exact equivalence mod q while allowing
	// zero-copy subslicing of u.Full and Y directly.
	if !useTwoEq {
		eq2MaxPos := new(big.Int).Set(colPos[fpEq1Cols])
		if t1AdvMax.Sign() > 0 {
			eq2MaxPos.Add(eq2MaxPos, t1AdvMax)
		}
		eq2MaxNeg := new(big.Int).Add(colNeg[fpEq1Cols], t1Bias)
		for c := 1; c < fpEq2Cols; c++ {
			eq2MaxPos.Add(eq2MaxPos, new(big.Int).Mul(bn254BigPowB[c], colPos[fpEq1Cols+c]))
			eq2MaxNeg.Add(eq2MaxNeg, new(big.Int).Mul(bn254BigPowB[c], colNeg[fpEq1Cols+c]))
		}
		t2Bias := new(big.Int).Quo(eq2MaxNeg, bn254B2)
		t2Max := new(big.Int).Quo(eq2MaxPos, bn254B2)
		t2Range := new(big.Int).Add(t2Max, t2Bias)
		t2Bits := t2Range.BitLen()
		t2PosMax := new(big.Int)
		if t2Bits > 0 {
			t2PosMax.Sub(new(big.Int).Lsh(bn254BigOne, uint(t2Bits)), bn254BigOne)
		}
		t2AdvMax := new(big.Int).Sub(t2PosMax, t2Bias)
		// Adversarial soundness assertion: |lhs2 - B^2*(t2Pos - t2Bias)| < q/2.
		eq2AdvPos := new(big.Int).Add(eq2MaxPos, new(big.Int).Mul(bn254B2, t2Bias))
		eq2AdvNeg := new(big.Int).Set(eq2MaxNeg)
		if t2AdvMax.Sign() > 0 {
			eq2AdvNeg.Add(eq2AdvNeg, new(big.Int).Mul(bn254B2, t2AdvMax))
		}
		if eq2AdvPos.Cmp(bn254HalfQ) >= 0 || eq2AdvNeg.Cmp(bn254HalfQ) >= 0 {
			panic(fmt.Sprintf("bqs AssertQuadModP: Eq2 adversarial bound (%d, %d bits) exceeds q/2",
				eq2AdvPos.BitLen(), eq2AdvNeg.BitLen()))
		}

		var t2PosVal *big.Int
		if b.synth {
			lhs2 := new(big.Int).Add(sumCols[fpEq1Cols], t1Val)
			for c := 1; c < fpEq2Cols; c++ {
				lhs2.Add(lhs2, new(big.Int).Mul(bn254BigPowB[c], sumCols[fpEq1Cols+c]))
			}
			t2Val, rem := new(big.Int).QuoRem(lhs2, bn254B2, new(big.Int))
			if rem.Sign() != 0 {
				panic(fmt.Sprintf("bqs AssertQuadModP: Eq2 not divisible by 2^108 (rem=%v)", rem))
			}
			t2PosVal = new(big.Int).Add(t2Val, t2Bias)
		}
		t2PosVec := b.allocBits(t2Bits, t2PosVal)

		// Emit zero-copy factored B^3-scaled Eq 2 products: (B^a * u_a) * (sum_{b=max(0,3-a)}^{4-a} B^b * Y_b).
		var eq2Prods []Product
		if len(groups) > 0 {
			eq2Prods = make([]Product, 0, len(groups)*fpLimbs)
			for gi := range groups {
				g := &groups[gi]
				for a := 0; a < fpLimbs; a++ {
					bLo := max(0, fpEq1Cols-a)
					bHi := fpLimbs - a
					eq2Prods = append(eq2Prods, Product{
						A: g.left.Full[fpFullOff[a]:fpFullOff[a+1]],
						B: g.yVec[g.yOff[bLo]:g.yOff[bHi]],
					})
				}
			}
		}

		// Emit B^3-scaled Eq 2 RHS: B^5*(t2Pos - t2Bias) - B^3*(t1Pos - t1Bias) - B^3*(adjConst + constVar + activeLins) + B^3*(kPos*p) (cols 3..4).
		b.accReset()
		b.accAddScaled(t2PosVec, bn254B5Fr)
		b.accAddScaled(t1PosVec, bn254NegB3Fr)
		{
			c0 := new(big.Int).Mul(t2Bias, bn254B2)
			c0.Neg(c0)
			c0.Add(c0, t1Bias)
			for c := 0; c < fpEq2Cols; c++ {
				if adjConstLimbs[fpEq1Cols+c].Sign() != 0 {
					c0.Sub(c0, new(big.Int).Mul(bn254BigPowB[c], adjConstLimbs[fpEq1Cols+c]))
				}
			}
			c0.Mul(c0, bn254B3)
			b.accAddTerm(0, frBig(c0))
		}
		for _, cv := range constVarProds {
			cFr := frInt64(cv.coeff)
			for j := 0; j < fpLimbs; j++ {
				if len(cv.x.Limbs[j]) == 0 {
					continue
				}
				var acc, term fr.Element
				for col := max(fpEq1Cols, j); col < fpLimbs; col++ {
					i := col - j
					if len(cv.c.Limbs[i]) == 0 {
						continue
					}
					term.Mul(&bn254NegPowB[col], &cv.c.Limbs[i][0].V)
					acc.Add(&acc, &term)
				}
				if !acc.IsZero() {
					acc.Mul(&acc, &cFr)
					b.accAddScaled(cv.x.Limbs[j], acc)
				}
			}
		}
		for _, lt := range activeLins {
			b.accAddScaled(lt.X.Full[fpFullOff[fpEq1Cols]:], frInt64(-lt.Coeff))
		}
		for i := 0; i < fpLimbs; i++ {
			if len(kLimbs[i]) > 0 {
				b.accAddScaled(kLimbs[i], bn254Eq2KScaleB3[i])
			}
		}
		if len(eq2Prods) == 0 {
			eq2Prods = []Product{{}}
		}
		b.Constraints = append(b.Constraints, Constraint{Products: eq2Prods, C: b.accFinish()})
	}

	// 9. Eq 3 (mod q): sum(varProds) = kPos_full*p - adjConst - sum(constVar) - sum(activeLins).
	var eq3Prods []Product
	if len(groups) > 0 {
		eq3Prods = make([]Product, 0, len(groups))
		for gi := range groups {
			g := &groups[gi]
			eq3Prods = append(eq3Prods, Product{A: g.left.Full, B: g.yVec})
		}
	}
	b.accReset()
	b.accAddScaled(kFull, bn254PModQ)
	if adjConst.Sign() != 0 {
		b.accAddTerm(0, frBig(new(big.Int).Neg(adjConst)))
	}
	for _, cv := range constVarProds {
		cFr := frInt64(cv.coeff)
		var sc fr.Element
		sc.Mul(&cFr, &cv.c.Full[0].V)
		sc.Neg(&sc)
		b.accAddScaled(cv.x.Full, sc)
	}
	for _, lt := range activeLins {
		b.accAddScaled(lt.X.Full, frInt64(-lt.Coeff))
	}
	if len(eq3Prods) == 0 {
		eq3Prods = []Product{{}}
	}
	b.Constraints = append(b.Constraints, Constraint{Products: eq3Prods, C: b.accFinish()})
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
	b.AssertQuadModP([]FpQuadTerm{{Coeff: 1, A: x, B: inv}}, nil, nil, b.oneFp)
	return inv
}

func (b *FpBuilder) FpNeg(x FpVar) FpVar {
	var negVal *big.Int
	if b.synth {
		negVal = new(big.Int).Sub(bn254P, x.Val)
		negVal.Mod(negVal, bn254P)
	}
	out := b.NewFpVar(negVal)
	b.AssertQuadModP(nil, []FpLinTerm{{Coeff: 1, X: x}, {Coeff: 1, X: out}}, nil, b.zeroFp)
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

// E2Sub computes x - y in F_{p^2} using 2 linear CRT(2^162, q) constraints per coordinate.
func (b *FpBuilder) E2Sub(x, y E2Var) E2Var {
	var outVal bn254.E2
	if b.synth {
		var ex, ey bn254.E2
		ex.A0.SetBigInt(x.A0.Val)
		ex.A1.SetBigInt(x.A1.Val)
		ey.A0.SetBigInt(y.A0.Val)
		ey.A1.SetBigInt(y.A1.Val)
		outVal.Sub(&ex, &ey)
	}
	out := b.NewE2Var(outVal)
	b.AssertQuadModP(nil, []FpLinTerm{{Coeff: 1, X: x.A0}, {Coeff: -1, X: y.A0}}, nil, out.A0)
	b.AssertQuadModP(nil, []FpLinTerm{{Coeff: 1, X: x.A1}, {Coeff: -1, X: y.A1}}, nil, out.A1)
	return out
}

// E2MulDiff computes x * (a - b) in F_{p^2} in 2 F_p constraints without materializing a - b.
func (b *FpBuilder) E2MulDiff(x, a, bv E2Var) E2Var {
	var outVal bn254.E2
	if b.synth {
		var ex, ea, eb, diff bn254.E2
		ex.A0.SetBigInt(x.A0.Val)
		ex.A1.SetBigInt(x.A1.Val)
		ea.A0.SetBigInt(a.A0.Val)
		ea.A1.SetBigInt(a.A1.Val)
		eb.A0.SetBigInt(bv.A0.Val)
		eb.A1.SetBigInt(bv.A1.Val)
		diff.Sub(&ea, &eb)
		outVal.Mul(&ex, &diff)
	}
	out := b.NewE2Var(outVal)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: x.A0, B: a.A0},
		{Coeff: -1, A: x.A0, B: bv.A0},
		{Coeff: -1, A: x.A1, B: a.A1},
		{Coeff: 1, A: x.A1, B: bv.A1},
	}, nil, nil, out.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: x.A0, B: a.A1},
		{Coeff: -1, A: x.A0, B: bv.A1},
		{Coeff: 1, A: x.A1, B: a.A0},
		{Coeff: -1, A: x.A1, B: bv.A0},
	}, nil, nil, out.A1)
	return out
}

// E2AssertNonZero proves x != 0 in F_{p^2} by witnessing x * inv == 1 (mod p^2).
func (b *FpBuilder) E2AssertNonZero(x E2Var) {
	var invVal bn254.E2
	if b.synth {
		var ex bn254.E2
		ex.A0.SetBigInt(x.A0.Val)
		ex.A1.SetBigInt(x.A1.Val)
		if ex.IsZero() {
			panic("bqs E2AssertNonZero: zero input")
		}
		invVal.Inverse(&ex)
	}
	inv := b.NewE2Var(invVal)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: x.A0, B: inv.A0},
		{Coeff: -1, A: x.A1, B: inv.A1},
	}, nil, nil, b.oneFp)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: x.A0, B: inv.A1},
		{Coeff: 1, A: x.A1, B: inv.A0},
	}, nil, nil, b.zeroFp)
}

func (b *FpBuilder) E2LinearMap(x E2Var, mat [2][2]*big.Int) E2Var {
	in := [2]FpVar{x.A0, x.A1}
	var res [2]FpVar
	for r := 0; r < 2; r++ {
		nonZero := 0
		onlyCol := -1
		for col := 0; col < 2; col++ {
			if mat[r][col].Sign() != 0 {
				nonZero++
				onlyCol = col
			}
		}
		if nonZero == 0 {
			res[r] = b.zeroFp
			continue
		}
		if nonZero == 1 && mat[r][onlyCol].Cmp(bn254BigOne) == 0 {
			res[r] = in[onlyCol]
			continue
		}
		var acc *big.Int
		if b.synth {
			acc = new(big.Int)
		}
		var prods []FpQuadTerm
		for col := 0; col < 2; col++ {
			if mat[r][col].Sign() == 0 {
				continue
			}
			prods = append(prods, FpQuadTerm{Coeff: 1, A: b.ConstFp(mat[r][col]), B: in[col]})
			if b.synth {
				acc.Add(acc, new(big.Int).Mul(mat[r][col], in[col].Val))
			}
		}
		if b.synth {
			acc.Mod(acc, bn254P)
		}
		res[r] = b.NewFpVar(acc)
		b.AssertQuadModP(prods, nil, nil, res[r])
	}
	return E2Var{A0: res[0], A1: res[1]}
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
	var outVal bn254.E12
	if b.synth {
		var xc [12]*big.Int
		for i := 0; i < 12; i++ {
			xc[i] = x.C[i].Val
		}
		ex := e12FromCoords(xc)
		outVal.Square(&ex)
	}
	out := b.NewE12Var(outVal)
	b.AssertE12Mul(x, x, out)
	return out
}

// AssertE12Mul asserts x * y == out in BN254 E12 using 12 multi-product F_p constraints (36 BQS rows total).
func (b *FpBuilder) AssertE12Mul(x, y, out E12Var) {
	b.AssertE12MulExpr(e12ToExpr(x), e12ToExpr(y), e12ToExpr(out))
}

// E12MulExpr multiplies two E12Expr values (which may contain deferred linear combinations
// and compile-time constants/zeros) and commits the reduced E12Var result.
func (b *FpBuilder) E12MulExpr(x, y E12Expr) E12Var {
	var outVal bn254.E12
	if b.synth {
		var xc, yc [12]*big.Int
		for i := 0; i < 12; i++ {
			xc[i] = x.C[i].evalModP()
			yc[i] = y.C[i].evalModP()
		}
		ex := e12FromCoords(xc)
		ey := e12FromCoords(yc)
		outVal.Mul(&ex, &ey)
	}
	out := b.NewE12Var(outVal)
	b.AssertE12MulExpr(x, y, e12ToExpr(out))
	return out
}

// AssertE12MulExpr asserts x * y == out in BN254 E12 where operands and output may contain
// deferred FpExpr linear combinations (zero extra constraints for sums/negations/constants).
func (b *FpBuilder) AssertE12MulExpr(x, y, out E12Expr) {
	// Pre-materialize any non-zero constant terms in x and y once across all 12 rows.
	var xConst, yConst [12]FpVar
	var xHasConst, yHasConst [12]bool
	for i := 0; i < 12; i++ {
		if x.C[i].Const != nil && x.C[i].Const.Sign() != 0 {
			xConst[i] = b.ConstFp(x.C[i].Const)
			xHasConst[i] = true
		}
		if y.C[i].Const != nil && y.C[i].Const.Sign() != 0 {
			yConst[i] = b.ConstFp(y.C[i].Const)
			yHasConst[i] = true
		}
	}

	var prods []FpQuadTerm
	var lins []FpLinTerm
	for r := 0; r < 12; r++ {
		prods = prods[:0]
		lins = lins[:0]
		cnst := new(big.Int)
		for i := 0; i < 12; i++ {
			xiTerms := x.C[i].Terms
			xiConst := xHasConst[i]
			if len(xiTerms) == 0 && !xiConst {
				continue
			}
			for j := 0; j < 12; j++ {
				c := e12MulCoeffs[r][i][j]
				if c == 0 {
					continue
				}
				yjTerms := y.C[j].Terms
				yjConst := yHasConst[j]
				if len(yjTerms) == 0 && !yjConst {
					continue
				}
				for _, tx := range xiTerms {
					for _, ty := range yjTerms {
						prods = append(prods, FpQuadTerm{Coeff: c * tx.Coeff * ty.Coeff, A: tx.X, B: ty.X})
					}
					if yjConst {
						prods = append(prods, FpQuadTerm{Coeff: c * tx.Coeff, A: yConst[j], B: tx.X})
					}
				}
				if xiConst {
					for _, ty := range yjTerms {
						prods = append(prods, FpQuadTerm{Coeff: c * ty.Coeff, A: xConst[i], B: ty.X})
					}
					if yjConst {
						t := new(big.Int).Mul(x.C[i].Const, y.C[j].Const)
						t.Mul(t, big.NewInt(c))
						cnst.Add(cnst, t)
					}
				}
			}
		}
		for _, to := range out.C[r].Terms {
			lins = append(lins, FpLinTerm{Coeff: -to.Coeff, X: to.X})
		}
		if out.C[r].Const != nil && out.C[r].Const.Sign() != 0 {
			cnst.Sub(cnst, out.C[r].Const)
		}
		b.AssertQuadModP(prods, lins, cnst, b.zeroFp)
	}
}

// E12MulBy34 multiplies x by sparse E12 element (1, 0, 0, c3, c4, 0) in 12 F_p constraints.
func (b *FpBuilder) E12MulBy34(x E12Var, c3, c4 E2Var) E12Var {
	sparse := E12Var{
		C: [12]FpVar{
			b.oneFp, b.zeroFp,
			b.zeroFp, b.zeroFp,
			b.zeroFp, b.zeroFp,
			c3.A0, c3.A1,
			c4.A0, c4.A1,
			b.zeroFp, b.zeroFp,
		},
	}
	return b.E12Mul(x, sparse)
}

// E12Mul034By034Expr multiplies two sparse affine 034 E12 elements
// (1, 0, 0, c3, c4, 0) * (1, 0, 0, d3, d4, 0) into an E12Expr using only 6 F_p constraints:
//   C0.B0 = 1 + (9 + u) * c4 * d4  (2 F_p constraints)
//   C0.B1 = c3 * d3                (2 F_p constraints)
//   C0.B2 = c3 * d4 + c4 * d3      (2 F_p constraints)
//   C1.B0 = c3 + d3                (0 constraints: deferred FpExpr!)
//   C1.B1 = c4 + d4                (0 constraints: deferred FpExpr!)
//   C1.B2 = 0                      (0 constraints)
func (b *FpBuilder) E12Mul034By034Expr(c3, c4, d3, d4 E2Var) E12Expr {
	var hostP0, hostP1, hostP2 bn254.E2
	if b.synth {
		var ec3, ec4, ed3, ed4, t1, t2 bn254.E2
		ec3.A0.SetBigInt(c3.A0.Val)
		ec3.A1.SetBigInt(c3.A1.Val)
		ec4.A0.SetBigInt(c4.A0.Val)
		ec4.A1.SetBigInt(c4.A1.Val)
		ed3.A0.SetBigInt(d3.A0.Val)
		ed3.A1.SetBigInt(d3.A1.Val)
		ed4.A0.SetBigInt(d4.A0.Val)
		ed4.A1.SetBigInt(d4.A1.Val)

		hostP0.Mul(&ec4, &ed4).MulByNonResidue(&hostP0)
		hostP0.A0.Add(&hostP0.A0, new(fp.Element).SetOne())
		hostP1.Mul(&ec3, &ed3)
		t1.Mul(&ec3, &ed4)
		t2.Mul(&ec4, &ed3)
		hostP2.Add(&t1, &t2)
	}
	p0 := b.NewE2Var(hostP0)
	p1 := b.NewE2Var(hostP1)
	p2 := b.NewE2Var(hostP2)

	// P0 = 1 + (9 + u) * (c4 * d4):
	//   A0 = 1 + 9*(c4.A0*d4.A0 - c4.A1*d4.A1) - (c4.A0*d4.A1 + c4.A1*d4.A0)
	//   A1 = (c4.A0*d4.A0 - c4.A1*d4.A1) + 9*(c4.A0*d4.A1 + c4.A1*d4.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 9, A: c4.A0, B: d4.A0},
		{Coeff: -9, A: c4.A1, B: d4.A1},
		{Coeff: -1, A: c4.A0, B: d4.A1},
		{Coeff: -1, A: c4.A1, B: d4.A0},
	}, nil, bn254BigOne, p0.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: c4.A0, B: d4.A0},
		{Coeff: -1, A: c4.A1, B: d4.A1},
		{Coeff: 9, A: c4.A0, B: d4.A1},
		{Coeff: 9, A: c4.A1, B: d4.A0},
	}, nil, nil, p0.A1)

	// P1 = c3 * d3
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: c3.A0, B: d3.A0},
		{Coeff: -1, A: c3.A1, B: d3.A1},
	}, nil, nil, p1.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: c3.A0, B: d3.A1},
		{Coeff: 1, A: c3.A1, B: d3.A0},
	}, nil, nil, p1.A1)

	// P2 = c3 * d4 + c4 * d3
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: c3.A0, B: d4.A0},
		{Coeff: -1, A: c3.A1, B: d4.A1},
		{Coeff: 1, A: c4.A0, B: d3.A0},
		{Coeff: -1, A: c4.A1, B: d3.A1},
	}, nil, nil, p2.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: c3.A0, B: d4.A1},
		{Coeff: 1, A: c3.A1, B: d4.A0},
		{Coeff: 1, A: c4.A0, B: d3.A1},
		{Coeff: 1, A: c4.A1, B: d3.A0},
	}, nil, nil, p2.A1)

	return E12Expr{
		C: [12]FpExpr{
			fpExprVar(p0.A0), fpExprVar(p0.A1),
			fpExprVar(p1.A0), fpExprVar(p1.A1),
			fpExprVar(p2.A0), fpExprVar(p2.A1),
			fpExprSum2(c3.A0, d3.A0), fpExprSum2(c3.A1, d3.A1),
			fpExprSum2(c4.A0, d4.A0), fpExprSum2(c4.A1, d4.A1),
			{}, {},
		},
	}
}

// E12FrobeniusMapExpr applies an exact 12x12 F_p linear map, keeping +1, -1, and 0 rows
// as deferred zero-constraint FpExpr entries.
func (b *FpBuilder) E12FrobeniusMapExpr(x E12Var, mat [12][12]*big.Int) E12Expr {
	var out E12Expr
	for r := 0; r < 12; r++ {
		nonZero := 0
		onlyCol := -1
		for col := 0; col < 12; col++ {
			if mat[r][col].Sign() != 0 {
				nonZero++
				onlyCol = col
			}
		}
		if nonZero == 0 {
			continue
		}
		if nonZero == 1 {
			if mat[r][onlyCol].Cmp(bn254BigOne) == 0 {
				out.C[r] = fpExprVar(x.C[onlyCol])
				continue
			}
			if mat[r][onlyCol].Cmp(bn254PMinus1) == 0 {
				out.C[r] = fpExprNegVar(x.C[onlyCol])
				continue
			}
		}
		var prods []FpQuadTerm
		var acc *big.Int
		if b.synth {
			acc = new(big.Int)
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
		v := b.NewFpVar(acc)
		b.AssertQuadModP(prods, nil, nil, v)
		out.C[r] = fpExprVar(v)
	}
	return out
}

// E12FrobeniusMap applies an exact 12x12 F_p Frobenius linear map (Frob1, Frob2, or Frob3).
func (b *FpBuilder) E12FrobeniusMap(x E12Var, mat [12][12]*big.Int) E12Var {
	expr := b.E12FrobeniusMapExpr(x, mat)
	var out E12Var
	for r := 0; r < 12; r++ {
		e := expr.C[r]
		if len(e.Terms) == 1 && e.Terms[0].Coeff == 1 && e.Const == nil {
			out.C[r] = e.Terms[0].X
			continue
		}
		if len(e.Terms) == 1 && e.Terms[0].Coeff == -1 && e.Const == nil {
			out.C[r] = b.FpNeg(e.Terms[0].X)
			continue
		}
		if len(e.Terms) == 0 {
			if e.Const == nil {
				out.C[r] = b.zeroFp
			} else {
				out.C[r] = b.ConstFp(e.Const)
			}
			continue
		}
		var val *big.Int
		if b.synth {
			val = e.evalModP()
		}
		v := b.NewFpVar(val)
		b.AssertQuadModP(nil, e.Terms, e.Const, v)
		out.C[r] = v
	}
	return out
}

// AssertG1OnCurve asserts P.Y^2 == P.X^3 + 3 (mod p), which also rules out (0, 0),
// x == 0 (since Legendre(3|p) = -1), and y == 0 (since -3 is a non-cube mod p).
func (b *FpBuilder) AssertG1OnCurve(p G1Var) {
	x2 := b.FpMul(p.X, p.X)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: p.Y, B: p.Y},
		{Coeff: -1, A: x2, B: p.X},
	}, nil, big.NewInt(-3), b.zeroFp)
}

// AssertG1OnCurveWithSquares asserts P.Y^2 == P.X^3 + 3 (mod p) and returns (P.X^2, P.Y^2)
// so callers can reuse both squares without recomputing them.
func (b *FpBuilder) AssertG1OnCurveWithSquares(p G1Var) (x2, y2 FpVar) {
	x2 = b.FpMul(p.X, p.X)
	y2 = b.FpMul(p.Y, p.Y)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: -1, A: x2, B: p.X},
	}, []FpLinTerm{{Coeff: 1, X: y2}}, big.NewInt(-3), b.zeroFp)
	return x2, y2
}

// AssertG2OnTwist asserts Q.Y^2 == Q.X^3 + b' (mod p^2), ruling out (0, 0),
// fusing x2 * Q.X directly into the curve equation (4 F_p constraints instead of 6).
func (b *FpBuilder) AssertG2OnTwist(q G2Var) {
	x2 := b.E2Mul(q.X, q.X)
	// q.Y^2 - x2 * q.X - b' == 0 in E2
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: q.Y.A0, B: q.Y.A0},
		{Coeff: -1, A: q.Y.A1, B: q.Y.A1},
		{Coeff: -1, A: x2.A0, B: q.X.A0},
		{Coeff: 1, A: x2.A1, B: q.X.A1},
	}, nil, new(big.Int).Neg(bn254TwistB[0]), b.zeroFp)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: q.Y.A0, B: q.Y.A1},
		{Coeff: -1, A: x2.A0, B: q.X.A1},
		{Coeff: -1, A: x2.A1, B: q.X.A0},
	}, nil, new(big.Int).Neg(bn254TwistB[1]), b.zeroFp)
}
