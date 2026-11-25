package bqs

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// Groth16VK holds the BN254 Groth16 verifying key elements needed for a Praxis
// witness-encryption lock against a fixed statement (VK + public input sum K_sum).
type Groth16VK struct {
	AlphaNeg bn254.G1Affine // -alpha in G1
	Beta     bn254.G2Affine // beta in G2
	GammaNeg bn254.G2Affine // -gamma in G2
	DeltaNeg bn254.G2Affine // -delta in G2
}

// Groth16Proof holds a standard BN254 Groth16 proof (Ar, Bs, Krs) satisfying:
//
//	e(Ar, Bs) * e(Krs, -delta) * e(Ksum, -gamma) * e(-alpha, beta) == 1.
type Groth16Proof struct {
	Ar  bn254.G1Affine
	Bs  bn254.G2Affine
	Krs bn254.G1Affine
}

// LineAffVar holds an affine Miller-loop line evaluation (R0, R1) in E2.
type LineAffVar struct {
	R0, R1 E2Var
}

// ComputeBN254FinalExpWitness computes the Novakovic-Eagen (ePrint 2024/640) residue witness
// (residueWitnessInv, cubicNonResiduePower) for a BN254 Miller loop output f whose final
// exponentiation is 1:
//
//	f * cubicNonResiduePower * residueWitnessInv^(6x+2 + p^3 - p^2 + p) == 1
//
// where cubicNonResiduePower lies in F_{p^6} (C1 == 0) and residueWitnessInv != 0.
func ComputeBN254FinalExpWitness(millerLoop *bn254.E12) (residueWitnessInv, cubicNonResiduePower bn254.E12) {
	var ml, tmp, x3, x, rw, rwInv, one, root27 bn254.E12
	ml.Set(millerLoop)

	var exp1, exp2, rInv, mInv big.Int
	exp1.SetString("4030969696062745741797811005853058291874379204406359442560681893891674450106959530046539719647151210908190211459382793062006703141168852426020468083171325367934590379984666859998399967609544754664110191464072930598755441160008826659219834762354786403012110463250131961575955268597858015384895449311534622125256548620283853223733396368939858981844663598065852816056384933498610930035891058807598891752166582271931875150099691598048016175399382213304673796601585080509443902692818733420199004555566113537482054218823936116647313678747500267068559627206777530424029211671772692598157901876223857571299238046741502089890557442500582300718504160740314926185458079985126192563953772118929726791041828902047546977272656240744693339962973939047279285351052107950250121751682659529260304162131862468322644288196213423232132152125277136333208005221619443705106431645884840489295409272576227859206166894626854018093044908314720", 10)
	root27.C0.B1.A0.SetString("9483667112135124394372960210728142145589475128897916459350428495526310884707")
	root27.C0.B1.A1.SetString("4534159768373982659291990808346042891252278737770656686799127720849666919525")

	if one.Exp(ml, &exp1).IsOne() {
		cubicNonResiduePower.SetOne()
		rw.Set(&ml)
	} else if one.Exp(*ml.Mul(&ml, &root27), &exp1).IsOne() {
		cubicNonResiduePower.Set(&root27)
		rw.Set(&ml)
	} else {
		cubicNonResiduePower.Square(&root27)
		rw.Mul(&ml, &root27)
	}

	rInv.SetString("495819184011867778744231927046742333492451180917315223017345540833046880485481720031136878341141903241966521818658471092566752321606779256340158678675679238405722886654128392203338228575623261160538734808887996935946888297414610216445334190959815200956855428635568184508263913274453942864817234480763055154719338281461936129150171789463489422401982681230261920147923652438266934726901346095892093443898852488218812468761027620988447655860644584419583586883569984588067403598284748297179498734419889699245081714359110559679136004228878808158639412436468707589339209058958785568729925402190575720856279605832146553573981587948304340677613460685405477047119496887534881410757668344088436651291444274840864486870663164657544390995506448087189408281061890434467956047582679858345583941396130713046072603335601764495918026585155498301896749919393", 10)
	rw.Exp(rw, &rInv)

	mInv.SetString("17840267520054779749190587238017784600702972825655245554504342129614427201836516118803396948809179149954197175783449826546445899524065131269177708416982407215963288737761615699967145070776364294542559324079147363363059480104341231360692143673915822421222230661528586799190306058519400019024762424366780736540525310403098758015600523609594113357130678138304964034267260758692953579514899054295817541844330584721967571697039986079722203518034173581264955381924826388858518077894154909963532054519350571947910625755075099598588672669612434444513251495355121627496067454526862754597351094345783576387352673894873931328099247263766690688395096280633426669535619271711975898132416216382905928886703963310231865346128293216316379527200971959980873989485521004596686352787540034457467115536116148612884807380187255514888720048664139404687086409399", 10)
	rw.Exp(rw, &mInv)

	rwInv.Inverse(&rw)
	exp2.SetString("149295173928249842288807815031594751550902933496531831205951181255247201855813315927649619246190785589192230054051214557852100116339587126889646966043382421034614458517950624444385183985538694617189266350521219651805757080000326913304438324531658755667115202342597480058368713651772519088329461085612393412046538837788290860138273939590365147475728281409846400594680923462911515927255224400281440435265428973034513894448136725853630228718495637529802733207466114092942366766400693830377740909465411612499335341437923559875826432546203713595131838044695464089778859691547136762894737106526809539677749557286722299625576201574095640767352005953344997266128077036486155280146436004404804695964512181557316554713802082990544197776406442186936269827816744738898152657469728130713344598597476387715653492155415311971560450078713968012341037230430349766855793764662401499603533676762082513303932107208402000670112774382027", 10)
	x.Exp(rw, &exp2)

	x3.Square(&x).Mul(&x3, &x).Mul(&x3, &rwInv)
	t := 0
	for !x3.IsOne() {
		t++
		tmp.Square(&x3)
		x3.Mul(&tmp, &x3)
	}
	for t != 0 {
		x.Mul(&x, tmp.Exp(root27, &exp2))
		x3.Square(&x).Mul(&x3, &x).Mul(&x3, &rwInv)
		t = 0
		for !x3.IsOne() {
			t++
			tmp.Square(&x3)
			x3.Mul(&tmp, &x3)
		}
	}
	residueWitnessInv.Inverse(&x)
	return residueWitnessInv, cubicNonResiduePower
}

// evalLineDirectBQS evaluates an affine line of slope lam through point T = (tX, tY) at Ar
// WITHOUT materializing the intermediate r1 = lam*tX - tY:
//
//	c3 = lam * arXNegOverY           (= -lam * Ar.X / Ar.Y)
//	Ar.X * c4 + c3 * tX - arXNegOverY * tY == 0
//
// Soundness: AssertG1OnCurve(Ar) forces Ar.X != 0 (Legendre(3|p) = -1) and Ar.Y != 0 (-3 non-cube),
// so dividing by Ar.X uniquely forces c4 == (lam*tX - tY) / Ar.Y (mod p).
func evalLineDirectBQS(b *FpBuilder, lam E2Var, t G2Var, arX, arXNegOverY FpVar, hostLam bn254.E2, hostT bn254.G2Affine, hostArXNegOverY, hostArYInv fp.Element) (E2Var, E2Var) {
	c3 := b.E2MulByFp(lam, arXNegOverY)

	var hostC4 bn254.E2
	if b.synth {
		hostC4.Mul(&hostLam, &hostT.X).Sub(&hostC4, &hostT.Y)
		hostC4.A0.Mul(&hostC4.A0, &hostArYInv)
		hostC4.A1.Mul(&hostC4.A1, &hostArYInv)
	}
	c4 := b.NewE2Var(hostC4)

	// Ar.X * c4 + c3 * t.X - arXNegOverY * t.Y == 0 in E2
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: arX, B: c4.A0},
		{Coeff: 1, A: c3.A0, B: t.X.A0},
		{Coeff: -1, A: c3.A1, B: t.X.A1},
		{Coeff: -1, A: arXNegOverY, B: t.Y.A0},
	}, nil, nil, b.zeroFp)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: arX, B: c4.A1},
		{Coeff: 1, A: c3.A0, B: t.X.A1},
		{Coeff: 1, A: c3.A1, B: t.X.A0},
		{Coeff: -1, A: arXNegOverY, B: t.Y.A1},
	}, nil, nil, b.zeroFp)

	return c3, c4
}

// g2DoubleStepBQS computes 2*accQ and its tangent slope lam in 6 F_p constraints (skipping r1).
func g2DoubleStepBQS(b *FpBuilder, accQ G2Var, hostQ *bn254.G2Affine) (G2Var, E2Var, bn254.E2) {
	var hostLambda, hostXr, hostYr bn254.E2
	if b.synth {
		var n, d bn254.E2
		n.Square(&hostQ.X)
		hostLambda.Double(&n).Add(&hostLambda, &n)
		d.Double(&hostQ.Y)
		hostLambda.Div(&hostLambda, &d)
		hostXr.Square(&hostLambda).Sub(&hostXr, &hostQ.X).Sub(&hostXr, &hostQ.X)
		hostYr.Sub(&hostQ.X, &hostXr).Mul(&hostYr, &hostLambda).Sub(&hostYr, &hostQ.Y)
		hostQ.X.Set(&hostXr)
		hostQ.Y.Set(&hostYr)
	}
	lam := b.NewE2Var(hostLambda)
	xr := b.NewE2Var(hostXr)
	yr := b.NewE2Var(hostYr)

	// 1. 2 * y * lam == 3 * x^2
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: accQ.Y.A0, B: lam.A0},
		{Coeff: -2, A: accQ.Y.A1, B: lam.A1},
		{Coeff: -3, A: accQ.X.A0, B: accQ.X.A0},
		{Coeff: 3, A: accQ.X.A1, B: accQ.X.A1},
	}, nil, nil, b.zeroFp)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: accQ.Y.A0, B: lam.A1},
		{Coeff: 2, A: accQ.Y.A1, B: lam.A0},
		{Coeff: -6, A: accQ.X.A0, B: accQ.X.A1},
	}, nil, nil, b.zeroFp)

	// 2. xr == lam^2 - 2 * x
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: lam.A0},
		{Coeff: -1, A: lam.A1, B: lam.A1},
	}, []FpLinTerm{{Coeff: -2, X: accQ.X.A0}}, nil, xr.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: lam.A0, B: lam.A1},
	}, []FpLinTerm{{Coeff: -2, X: accQ.X.A1}}, nil, xr.A1)

	// 3. yr == lam * (x - xr) - y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A0},
		{Coeff: -1, A: lam.A1, B: accQ.X.A1},
		{Coeff: -1, A: lam.A0, B: xr.A0},
		{Coeff: 1, A: lam.A1, B: xr.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A0}}, nil, yr.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A1},
		{Coeff: 1, A: lam.A1, B: accQ.X.A0},
		{Coeff: -1, A: lam.A0, B: xr.A1},
		{Coeff: -1, A: lam.A1, B: xr.A0},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A1}}, nil, yr.A1)

	return G2Var{X: xr, Y: yr}, lam, hostLambda
}

// g2AddStepBQS computes accQ + a and its chord slope lam in 6 F_p constraints (skipping r1).
func g2AddStepBQS(b *FpBuilder, accQ, a G2Var, hostQ *bn254.G2Affine, hostA bn254.G2Affine) (G2Var, E2Var, bn254.E2) {
	var hostLam, hostXr, hostYr bn254.E2
	if b.synth {
		var n, d bn254.E2
		n.Sub(&hostA.Y, &hostQ.Y)
		d.Sub(&hostA.X, &hostQ.X)
		hostLam.Div(&n, &d)
		hostXr.Square(&hostLam).Sub(&hostXr, &hostQ.X).Sub(&hostXr, &hostA.X)
		hostYr.Sub(&hostQ.X, &hostXr).Mul(&hostYr, &hostLam).Sub(&hostYr, &hostQ.Y)
		hostQ.X.Set(&hostXr)
		hostQ.Y.Set(&hostYr)
	}
	lam := b.NewE2Var(hostLam)
	xr := b.NewE2Var(hostXr)
	yr := b.NewE2Var(hostYr)

	// 1. lam * (a.X - p.X) == a.Y - p.Y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: a.X.A0},
		{Coeff: -1, A: lam.A1, B: a.X.A1},
		{Coeff: -1, A: lam.A0, B: accQ.X.A0},
		{Coeff: 1, A: lam.A1, B: accQ.X.A1},
	}, []FpLinTerm{{Coeff: 1, X: accQ.Y.A0}}, nil, a.Y.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: a.X.A1},
		{Coeff: 1, A: lam.A1, B: a.X.A0},
		{Coeff: -1, A: lam.A0, B: accQ.X.A1},
		{Coeff: -1, A: lam.A1, B: accQ.X.A0},
	}, []FpLinTerm{{Coeff: 1, X: accQ.Y.A1}}, nil, a.Y.A1)

	// 2. xr == lam^2 - p.X - a.X
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: lam.A0},
		{Coeff: -1, A: lam.A1, B: lam.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A0}, {Coeff: -1, X: a.X.A0}}, nil, xr.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: lam.A0, B: lam.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A1}, {Coeff: -1, X: a.X.A1}}, nil, xr.A1)

	// 3. yr == lam * (p.X - xr) - p.Y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A0},
		{Coeff: -1, A: lam.A1, B: accQ.X.A1},
		{Coeff: -1, A: lam.A0, B: xr.A0},
		{Coeff: 1, A: lam.A1, B: xr.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A0}}, nil, yr.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A1},
		{Coeff: 1, A: lam.A1, B: accQ.X.A0},
		{Coeff: -1, A: lam.A0, B: xr.A1},
		{Coeff: -1, A: lam.A1, B: xr.A0},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A1}}, nil, yr.A1)

	return G2Var{X: xr, Y: yr}, lam, hostLam
}

// g2AddToTargetBQS enforces accQ + a == target in E'(F_{p^2}) (given caller proves a.X != accQ.X
// via the batched chord denominator non-zero product) and returns the chord slope lam in 6 F_p constraints.
// Used on the final Frobenius step to simultaneously produce the lPsi Miller line slope and prove the
// exact BN254 G2[r] prime-order subgroup identity [6x+2]Bs + psi(Bs) - psi^2(Bs) == -psi^3(Bs).
func g2AddToTargetBQS(b *FpBuilder, accQ, a, target G2Var, hostQ, hostA bn254.G2Affine) (E2Var, bn254.E2) {
	var hostLam bn254.E2
	if b.synth {
		var n, d bn254.E2
		n.Sub(&hostA.Y, &hostQ.Y)
		d.Sub(&hostA.X, &hostQ.X)
		hostLam.Div(&n, &d)
	}
	lam := b.NewE2Var(hostLam)

	// 1. lam * (a.X - accQ.X) == a.Y - accQ.Y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: a.X.A0},
		{Coeff: -1, A: lam.A1, B: a.X.A1},
		{Coeff: -1, A: lam.A0, B: accQ.X.A0},
		{Coeff: 1, A: lam.A1, B: accQ.X.A1},
	}, []FpLinTerm{{Coeff: 1, X: accQ.Y.A0}}, nil, a.Y.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: a.X.A1},
		{Coeff: 1, A: lam.A1, B: a.X.A0},
		{Coeff: -1, A: lam.A0, B: accQ.X.A1},
		{Coeff: -1, A: lam.A1, B: accQ.X.A0},
	}, []FpLinTerm{{Coeff: 1, X: accQ.Y.A1}}, nil, a.Y.A1)

	// 2. target.X == lam^2 - accQ.X - a.X
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: lam.A0},
		{Coeff: -1, A: lam.A1, B: lam.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A0}, {Coeff: -1, X: a.X.A0}}, nil, target.X.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: lam.A0, B: lam.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A1}, {Coeff: -1, X: a.X.A1}}, nil, target.X.A1)

	// 3. target.Y == lam * (accQ.X - target.X) - accQ.Y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A0},
		{Coeff: -1, A: lam.A1, B: accQ.X.A1},
		{Coeff: -1, A: lam.A0, B: target.X.A0},
		{Coeff: 1, A: lam.A1, B: target.X.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A0}}, nil, target.Y.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A1},
		{Coeff: 1, A: lam.A1, B: accQ.X.A0},
		{Coeff: -1, A: lam.A0, B: target.X.A1},
		{Coeff: -1, A: lam.A1, B: target.X.A0},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A1}}, nil, target.Y.A1)

	return lam, hostLam
}

// g2DoubleAndAddStepBQS computes 2*accQ ± a and both chord slopes (l1, l2) in 10 F_p constraints
// (skipping r11, r12, and supporting negA directly without allocating -a.Y).
func g2DoubleAndAddStepBQS(b *FpBuilder, accQ, a G2Var, negA bool, hostQ *bn254.G2Affine, hostA bn254.G2Affine) (G2Var, E2Var, E2Var, bn254.E2, bn254.E2) {
	var hostL1, hostX3, hostL2, hostX4, hostY4 bn254.E2
	if b.synth {
		effA := hostA
		if negA {
			effA.Y.Neg(&effA.Y)
		}
		var A, B, A2, B2, t, U, invA, invU bn254.E2
		A.Sub(&hostQ.X, &effA.X)
		B.Sub(&hostQ.Y, &effA.Y)
		A2.Square(&A)
		B2.Square(&B)
		t.Double(&hostQ.X).Add(&t, &effA.X)
		U.Mul(&t, &A2).Sub(&B2, &U)
		invA.Inverse(&A)
		invU.Inverse(&U)
		hostL1.Mul(&B, &invA)
		hostX3.Square(&hostL1).Sub(&hostX3, &hostQ.X).Sub(&hostX3, &effA.X)
		hostL2.Double(&hostQ.Y).Mul(&hostL2, &A2).Mul(&hostL2, &invU).Add(&hostL2, &hostL1).Neg(&hostL2)
		hostX4.Square(&hostL2).Sub(&hostX4, &hostQ.X).Sub(&hostX4, &hostX3)
		hostY4.Sub(&hostQ.X, &hostX4).Mul(&hostY4, &hostL2).Sub(&hostY4, &hostQ.Y)
		hostQ.X.Set(&hostX4)
		hostQ.Y.Set(&hostY4)
	}
	l1 := b.NewE2Var(hostL1)
	x3 := b.NewE2Var(hostX3)
	l2 := b.NewE2Var(hostL2)
	x4 := b.NewE2Var(hostX4)
	y4 := b.NewE2Var(hostY4)

	// 1. l1 * (p.X - a.X) == p.Y - (+1 or -1)*a.Y  ==>  l1*(p.X - a.X) + signA*a.Y == p.Y
	signA := int64(1)
	if negA {
		signA = -1
	}
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l1.A0, B: accQ.X.A0},
		{Coeff: -1, A: l1.A1, B: accQ.X.A1},
		{Coeff: -1, A: l1.A0, B: a.X.A0},
		{Coeff: 1, A: l1.A1, B: a.X.A1},
	}, []FpLinTerm{{Coeff: signA, X: a.Y.A0}}, nil, accQ.Y.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l1.A0, B: accQ.X.A1},
		{Coeff: 1, A: l1.A1, B: accQ.X.A0},
		{Coeff: -1, A: l1.A0, B: a.X.A1},
		{Coeff: -1, A: l1.A1, B: a.X.A0},
	}, []FpLinTerm{{Coeff: signA, X: a.Y.A1}}, nil, accQ.Y.A1)

	// 2. x3 == l1^2 - p.X - a.X
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l1.A0, B: l1.A0},
		{Coeff: -1, A: l1.A1, B: l1.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A0}, {Coeff: -1, X: a.X.A0}}, nil, x3.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: l1.A0, B: l1.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A1}, {Coeff: -1, X: a.X.A1}}, nil, x3.A1)

	// 3. (l2 + l1) * (x3 - p.X) + 2*p.Y == 0
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: x3.A0},
		{Coeff: -1, A: l2.A1, B: x3.A1},
		{Coeff: 1, A: l1.A0, B: x3.A0},
		{Coeff: -1, A: l1.A1, B: x3.A1},
		{Coeff: -1, A: l2.A0, B: accQ.X.A0},
		{Coeff: 1, A: l2.A1, B: accQ.X.A1},
		{Coeff: -1, A: l1.A0, B: accQ.X.A0},
		{Coeff: 1, A: l1.A1, B: accQ.X.A1},
	}, []FpLinTerm{{Coeff: 2, X: accQ.Y.A0}}, nil, b.zeroFp)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: x3.A1},
		{Coeff: 1, A: l2.A1, B: x3.A0},
		{Coeff: 1, A: l1.A0, B: x3.A1},
		{Coeff: 1, A: l1.A1, B: x3.A0},
		{Coeff: -1, A: l2.A0, B: accQ.X.A1},
		{Coeff: -1, A: l2.A1, B: accQ.X.A0},
		{Coeff: -1, A: l1.A0, B: accQ.X.A1},
		{Coeff: -1, A: l1.A1, B: accQ.X.A0},
	}, []FpLinTerm{{Coeff: 2, X: accQ.Y.A1}}, nil, b.zeroFp)

	// 4. x4 == l2^2 - p.X - x3
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: l2.A0},
		{Coeff: -1, A: l2.A1, B: l2.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A0}, {Coeff: -1, X: x3.A0}}, nil, x4.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: l2.A0, B: l2.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A1}, {Coeff: -1, X: x3.A1}}, nil, x4.A1)

	// 5. y4 == l2 * (p.X - x4) - p.Y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: accQ.X.A0},
		{Coeff: -1, A: l2.A1, B: accQ.X.A1},
		{Coeff: -1, A: l2.A0, B: x4.A0},
		{Coeff: 1, A: l2.A1, B: x4.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A0}}, nil, y4.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: accQ.X.A1},
		{Coeff: 1, A: l2.A1, B: accQ.X.A0},
		{Coeff: -1, A: l2.A0, B: x4.A1},
		{Coeff: -1, A: l2.A1, B: x4.A0},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A1}}, nil, y4.A1)

	return G2Var{X: x4, Y: y4}, l1, l2, hostL1, hostL2
}

// evalConstLinePairProjectiveBQS computes the exact product of two precomputed Delta lines
// scaled by Krs.Y^2 in F_p^* (which is annihilated by the easy final exponentiation p^6 - 1):
//
//	(Krs.Y * L0(Krs)) * (Krs.Y * L1(Krs))
//	  where Krs.Y * L_k(Krs) = Krs.Y + (-R0_k * Krs.X)*w + R1_k*v*w.
//
// All five E2 products collapse to compile-time constants times (1, Krs.X, Krs.Y, Krs.X^2, Krs.Y^2, Krs.X*Krs.Y):
//   C0.B0 = Krs.Y^2 + xi*R1_0*R1_1             (0 constraints: deferred FpExpr!)
//   C0.B1 = (R0_0 * R0_1) * Krs.X^2            (2 linear const*var constraints)
//   C0.B2 = -(R0_0*R1_1 + R1_0*R0_1) * Krs.X   (2 linear const*var constraints)
//   C1.B0 = -(R0_0 + R0_1) * (Krs.X * Krs.Y)   (2 linear const*var constraints)
//   C1.B1 = (R1_0 + R1_1) * Krs.Y              (2 linear const*var constraints)
//   C1.B2 = 0                                  (0 constraints)
func evalConstLinePairProjectiveBQS(
	b *FpBuilder,
	l0, l1 bn254.LineEvaluationAff,
	krsX, krsY, krsX2, krsY2, krsXY FpVar,
) E12Expr {
	var a0, a1, k0, k1, k2, k3, k4, t1, t2 bn254.E2
	a0.Neg(&l0.R0)
	a1.Neg(&l1.R0)
	k0.Mul(&l0.R1, &l1.R1).MulByNonResidue(&k0)
	k1.Mul(&a0, &a1)
	t1.Mul(&a0, &l1.R1)
	t2.Mul(&l0.R1, &a1)
	k2.Add(&t1, &t2)
	k3.Add(&a0, &a1)
	k4.Add(&l0.R1, &l1.R1)

	p1 := b.E2MulByFp(b.ConstE2(k1), krsX2)
	p2 := b.E2MulByFp(b.ConstE2(k2), krsX)
	p3 := b.E2MulByFp(b.ConstE2(k3), krsXY)
	p4 := b.E2MulByFp(b.ConstE2(k4), krsY)

	return E12Expr{
		C: [12]FpExpr{
			fpExprVarPlusConst(krsY2, k0.A0.BigInt(new(big.Int))),
			fpExprConst(k0.A1.BigInt(new(big.Int))),
			fpExprVar(p1.A0), fpExprVar(p1.A1),
			fpExprVar(p2.A0), fpExprVar(p2.A1),
			fpExprVar(p3.A0), fpExprVar(p3.A1),
			fpExprVar(p4.A0), fpExprVar(p4.A1),
			{}, {},
		},
	}
}

// buildGroth16BQS builds the complete BN254 Groth16 verifier BQS for a fixed verifying key
// and fixed public input sum K_sum. When proof != nil, simultaneously synthesizes the exact
// Boolean witness vector w []bool.
//
// Proved statement:
//   - Ar, Krs lie on BN254 G1 (y^2 = x^3 + 3), implying Ar.X, Ar.Y, Krs.X, Krs.Y != 0 mod p
//   - Bs lies on BN254 G2 twist (y^2 = x^3 + 3/(9+u)) AND in the prime-order subgroup G2[r] \ {O},
//     proved via batched non-zero chord denominators across the entire [6x+2]Bs + psi(Bs) - psi^2(Bs)
//     trajectory together with the exact Frobenius endomorphism check [6x+2]Bs + psi(Bs) - psi^2(Bs) == -psi^3(Bs)
//     (where gcd(Norm(Phi_Ate), #E'(F_{p^2})) == r is strictly asserted in init())
//   - e(Ar, Bs) * e(Krs, -delta) * e(Ksum, -gamma) * e(-alpha, beta) == 1 in G_T
//     verified via Novakovic-Eagen (ePrint 2024/640) folded Miller loop + cubic non-residue
//     witness w_i in F_{p^6} + non-zero invertibility c * c^{-1} == 1.
func buildGroth16BQS(vk Groth16VK, publicKsum bn254.G1Affine, proof *Groth16Proof) (*System, []bool, error) {
	synth := proof != nil

	// Precompute constant Miller loop factor for the two fixed pairs:
	//   fixedML = MillerLoopFixedQ([Ksum, -alpha], [lines(-gamma), lines(beta)])
	linesGamma := bn254.PrecomputeLines(vk.GammaNeg)
	linesBeta := bn254.PrecomputeLines(vk.Beta)
	linesDelta := bn254.PrecomputeLines(vk.DeltaNeg)
	fixedML, err := bn254.MillerLoopFixedQ(
		[]bn254.G1Affine{publicKsum, vk.AlphaNeg},
		[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{linesGamma, linesBeta},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("precompute fixed VK MillerLoop: %w", err)
	}

	// Compute the exact exponent of Krs.Y in F_p^* accumulated by projective Delta line-pairs
	// across non-zero Miller loop bits and the final Frobenius step.
	var krsYScaleExp big.Int
	for i := len(bn254.LoopCounter) - 2; i >= 0; i-- {
		krsYScaleExp.Lsh(&krsYScaleExp, 1)
		if bn254.LoopCounter[i] != 0 {
			krsYScaleExp.Add(&krsYScaleExp, big.NewInt(2))
		}
	}
	krsYScaleExp.Add(&krsYScaleExp, big.NewInt(2))

	var hostAr, hostKrs bn254.G1Affine
	var hostBs bn254.G2Affine
	var hostResWitnessInv, hostResWitness, hostWi bn254.E12
	var hostArYInv, hostArXNegOverY, hostKrsXNegOverY fp.Element
	if synth {
		if proof.Ar.IsInfinity() || !proof.Ar.IsOnCurve() {
			return nil, nil, fmt.Errorf("invalid Groth16 proof: Ar not on BN254 G1")
		}
		if proof.Krs.IsInfinity() || !proof.Krs.IsOnCurve() {
			return nil, nil, fmt.Errorf("invalid Groth16 proof: Krs not on BN254 G1")
		}
		if proof.Bs.IsInfinity() || !proof.Bs.IsOnCurve() {
			return nil, nil, fmt.Errorf("invalid Groth16 proof: Bs not on BN254 G2 twist")
		}
		if !proof.Bs.IsInSubGroup() {
			return nil, nil, fmt.Errorf("invalid Groth16 proof: Bs not in BN254 G2[r] prime-order subgroup")
		}
		hostAr = proof.Ar
		hostKrs = proof.Krs
		hostBs = proof.Bs
		linesBs := bn254.PrecomputeLines(hostBs)
		totalML, err := bn254.MillerLoopFixedQ(
			[]bn254.G1Affine{hostAr, hostKrs, publicKsum, vk.AlphaNeg},
			[][2][len(bn254.LoopCounter)]bn254.LineEvaluationAff{linesBs, linesDelta, linesGamma, linesBeta},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("compute host MillerLoop: %w", err)
		}
		// Scale totalML by Krs.Y^krsYScaleExp in F_p^* \subset F_{p^6}^*.
		// Because F_p^* is in the kernel of FinalExponentiation, this preserves pairing validity identically.
		var yScale fp.Element
		yScale.Exp(hostKrs.Y, &krsYScaleExp)
		var yScaleE12 bn254.E12
		yScaleE12.C0.B0.A0.Set(&yScale)
		totalML.Mul(&totalML, &yScaleE12)

		fe := bn254.FinalExponentiation(&totalML)
		if !fe.IsOne() {
			return nil, nil, fmt.Errorf("invalid Groth16 proof: pairing check failed")
		}
		hostResWitnessInv, hostWi = ComputeBN254FinalExpWitness(&totalML)
		hostResWitness.Inverse(&hostResWitnessInv)

		hostArYInv.Inverse(&hostAr.Y)
		hostArXNegOverY.Mul(&hostAr.X, &hostArYInv).Neg(&hostArXNegOverY)
		var hostKrsYInv fp.Element
		hostKrsYInv.Inverse(&hostKrs.Y)
		hostKrsXNegOverY.Mul(&hostKrs.X, &hostKrsYInv).Neg(&hostKrsXNegOverY)
	}

	b := NewFpBuilder(synth)

	// Allocate proof variables & enforce curve equations (rules out infinity and zero coordinates).
	ar := b.NewG1Var(hostAr)
	krs := b.NewG1Var(hostKrs)
	bs := b.NewG2Var(hostBs)
	b.AssertG1OnCurve(ar)
	krsX2, krsY2 := b.AssertG1OnCurveWithSquares(krs)
	b.AssertG2OnTwist(bs)

	// Precompute fused affine evaluation factors:
	//   arXNegOverY = -Ar.X / Ar.Y  via 1 constraint: Ar.Y * arXNegOverY + Ar.X == 0 (no arYInv needed!)
	//   krsYInv     = 1 / Krs.Y     (for single Delta lines on LoopCounter[i] == 0)
	//   krsXNegOverY = -Krs.X / Krs.Y via 1 constraint: Krs.Y * krsXNegOverY + Krs.X == 0
	//   krsXY       = Krs.X * Krs.Y (for projective Delta line pairs)
	var arXNegVal, krsXNegVal *big.Int
	if synth {
		arXNegVal = hostArXNegOverY.BigInt(new(big.Int))
		krsXNegVal = hostKrsXNegOverY.BigInt(new(big.Int))
	}
	arXNegOverY := b.NewFpVar(arXNegVal)
	b.AssertQuadModP([]FpQuadTerm{{Coeff: 1, A: ar.Y, B: arXNegOverY}}, []FpLinTerm{{Coeff: 1, X: ar.X}}, nil, b.zeroFp)

	krsYInv := b.FpInv(krs.Y)
	krsXNegOverY := b.NewFpVar(krsXNegVal)
	b.AssertQuadModP([]FpQuadTerm{{Coeff: 1, A: krs.Y, B: krsXNegOverY}}, []FpLinTerm{{Coeff: 1, X: krs.X}}, nil, b.zeroFp)
	krsXY := b.FpMul(krs.X, krs.Y)

	// Allocate Novakovic-Eagen residue witness c^{-1}, c (with c * c^{-1} == 1 ruling out 0==0)
	// and cubic non-residue power w_i constrained to F_{p^6} (C1 == 0!).
	cInv := b.NewE12Var(hostResWitnessInv)
	cVal := b.NewE12Var(hostResWitness)
	var oneE12 bn254.E12
	oneE12.SetOne()
	b.AssertE12Mul(cInv, cVal, b.ConstE12(oneE12))

	var wiCoords [12]*big.Int
	if synth {
		wiCoords = getE12Coords(&hostWi)
	}
	wi := E12Var{
		C: [12]FpVar{
			b.NewFpVar(wiCoords[0]), b.NewFpVar(wiCoords[1]),
			b.NewFpVar(wiCoords[2]), b.NewFpVar(wiCoords[3]),
			b.NewFpVar(wiCoords[4]), b.NewFpVar(wiCoords[5]),
			b.zeroFp, b.zeroFp, b.zeroFp, b.zeroFp, b.zeroFp, b.zeroFp, // strictly in F_{p^6}!
		},
	}

	var hostAccQ bn254.G2Affine
	if synth {
		hostAccQ = hostBs
	}
	accQ := bs
	res := cInv // LoopCounter[65] = 1 -> res starts at c^{-1}
	cInvExpr := e12ToExpr(cInv)
	cValExpr := e12ToExpr(cVal)

	evalConstLine := func(l bn254.LineEvaluationAff) (E2Var, E2Var) {
		return b.E2MulByFp(b.ConstE2(l.R0), krsXNegOverY), b.E2MulByFp(b.ConstE2(l.R1), krsYInv)
	}

	// Accumulate all affine G2 chord denominators (accQ.X - bs.X, phiBs.X - accQ.X, psiBs.X - accQ.X)
	// into a single F_{p^2} product and enforce denomProd * denomProdInv == 1 so no small-order
	// cofactor point (e.g. order 10069 dividing h2 = 2p - r) can satisfy lam * 0 == 0.
	var denomProd E2Var
	hasDenomProd := false
	addNonZeroDenom := func(aX, bX E2Var) {
		if !hasDenomProd {
			denomProd = b.E2Sub(aX, bX)
			hasDenomProd = true
		} else {
			denomProd = b.E2MulDiff(denomProd, aX, bX)
		}
	}

	for i := len(bn254.LoopCounter) - 2; i >= 0; i-- {
		res = b.E12Square(res)
		bit := bn254.LoopCounter[i]
		switch bit {
		case 0:
			prevQ := accQ
			hostPrevQ := hostAccQ
			var lam E2Var
			var hostLam bn254.E2
			accQ, lam, hostLam = g2DoubleStepBQS(b, accQ, &hostAccQ)
			c3, c4 := evalLineDirectBQS(b, lam, prevQ, ar.X, arXNegOverY, hostLam, hostPrevQ, hostArXNegOverY, hostArYInv)
			d3, d4 := evalConstLine(linesDelta[0][i])
			linePair := b.E12Mul034By034Expr(c3, c4, d3, d4)
			res = b.E12MulExpr(e12ToExpr(res), linePair)
		case 1, -1:
			negA := bit == -1
			prevQ := accQ
			hostPrevQ := hostAccQ
			addNonZeroDenom(prevQ.X, bs.X)
			var l1, l2 E2Var
			var hostL1, hostL2 bn254.E2
			accQ, l1, l2, hostL1, hostL2 = g2DoubleAndAddStepBQS(b, accQ, bs, negA, &hostAccQ, hostBs)
			c31, c41 := evalLineDirectBQS(b, l1, prevQ, ar.X, arXNegOverY, hostL1, hostPrevQ, hostArXNegOverY, hostArYInv)
			c32, c42 := evalLineDirectBQS(b, l2, prevQ, ar.X, arXNegOverY, hostL2, hostPrevQ, hostArXNegOverY, hostArYInv)
			bsPair := b.E12Mul034By034Expr(c31, c41, c32, c42)
			deltaPair := evalConstLinePairProjectiveBQS(b, linesDelta[0][i], linesDelta[1][i], krs.X, krs.Y, krsX2, krsY2, krsXY)
			if bit == 1 {
				res = b.E12MulExpr(e12ToExpr(res), cInvExpr)
			} else {
				res = b.E12MulExpr(e12ToExpr(res), cValExpr)
			}
			res = b.E12MulExpr(e12ToExpr(res), bsPair)
			res = b.E12MulExpr(e12ToExpr(res), deltaPair)
		}
	}

	// Final Frobenius lines: Q1 = psi(Bs), Q2 = -psi^2(Bs), and Q3 = -psi^3(Bs)
	// (note g2PsiYMat = I_2 -> 0 constraints for psiBs.Y, and (-psi^3(Bs)).Y == psi(Bs).Y -> 0 constraints!).
	phiBs := G2Var{
		X: b.E2LinearMap(bs.X, g2PhiXMat),
		Y: b.E2LinearMap(bs.Y, g2PhiYMat),
	}
	psiBs := G2Var{
		X: b.E2LinearMap(bs.X, g2PsiXMat),
		Y: b.E2LinearMap(bs.Y, g2PsiYMat),
	}
	negPsi3Bs := G2Var{
		X: b.E2LinearMap(bs.X, g2NegPsi3XMat),
		Y: phiBs.Y,
	}
	var hostPhiBs, hostPsiBs bn254.G2Affine
	if synth {
		hostPhiBs.X.Conjugate(&hostBs.X).MulByNonResidue1Power2(&hostPhiBs.X)
		hostPhiBs.Y.Conjugate(&hostBs.Y).MulByNonResidue1Power3(&hostPhiBs.Y)
		hostPsiBs.X.MulByNonResidue2Power2(&hostBs.X)
		hostPsiBs.Y.MulByNonResidue2Power3(&hostBs.Y).Neg(&hostPsiBs.Y)
	}

	prevQ := accQ
	hostPrevQ := hostAccQ
	addNonZeroDenom(phiBs.X, prevQ.X)
	accQ, lamPhi, hostLamPhi := g2AddStepBQS(b, accQ, phiBs, &hostAccQ, hostPhiBs)
	c3Phi, c4Phi := evalLineDirectBQS(b, lamPhi, prevQ, ar.X, arXNegOverY, hostLamPhi, hostPrevQ, hostArXNegOverY, hostArYInv)

	// Final Frobenius chord + exact G2[r] prime-order subgroup check:
	//   [6x+2]Bs + psi(Bs) - psi^2(Bs) == -psi^3(Bs)   <=>   Phi_Ate(Bs) == O   <=>   Bs in G2[r].
	addNonZeroDenom(psiBs.X, accQ.X)
	b.E2AssertNonZero(denomProd)
	lamPsi, hostLamPsi := g2AddToTargetBQS(b, accQ, psiBs, negPsi3Bs, hostAccQ, hostPsiBs)
	c3Psi, c4Psi := evalLineDirectBQS(b, lamPsi, accQ, ar.X, arXNegOverY, hostLamPsi, hostAccQ, hostArXNegOverY, hostArYInv)

	bsFrobPair := b.E12Mul034By034Expr(c3Phi, c4Phi, c3Psi, c4Psi)
	deltaFrobPair := evalConstLinePairProjectiveBQS(b, linesDelta[1][65], linesDelta[0][65], krs.X, krs.Y, krsX2, krsY2, krsXY)
	res = b.E12MulExpr(e12ToExpr(res), bsFrobPair)
	res = b.E12MulExpr(e12ToExpr(res), deltaFrobPair)

	// Fuse constant fixedML = MillerLoop(Ksum, -gamma) * MillerLoop(-alpha, beta) directly
	// into the 12x12 Frobenius-1 linear map on cInv:
	//   res * wi * frob3 * (fixedML * frob1) == frob2
	// Equivalent to: MillerLoop * Krs.Y^krsYScaleExp * wi * (cInv)^(6x+2 + p^3 - p^2 + p) == 1.
	var frob1FixedMat [12][12]*big.Int
	for col := 0; col < 12; col++ {
		var basis, f1, prod bn254.E12
		setE12Coord(&basis, col, bn254BigOne)
		f1.Frobenius(&basis)
		prod.Mul(&fixedML, &f1)
		coords := getE12Coords(&prod)
		for row := 0; row < 12; row++ {
			frob1FixedMat[row][col] = coords[row]
		}
	}

	frob1Scaled := b.E12FrobeniusMapExpr(cInv, frob1FixedMat)
	frob2 := b.E12FrobeniusMapExpr(cInv, e12Frob2Mat)
	frob3 := b.E12FrobeniusMapExpr(cInv, e12Frob3Mat)

	t1 := b.E12Mul(res, wi)
	t2 := b.E12MulExpr(frob3, frob1Scaled)
	b.AssertE12MulExpr(e12ToExpr(t1), e12ToExpr(t2), frob2)

	sys, err := b.System()
	if err != nil {
		return nil, nil, err
	}
	return sys, b.W, nil
}

// CompileGroth16Verifier compiles the BN254 Groth16 verifier BQS for a fixed verifying key
// and public input point K_sum without requiring a proof (used by the Praxis encryptor).
func CompileGroth16Verifier(vk Groth16VK, publicKsum bn254.G1Affine) (*System, error) {
	sys, _, err := buildGroth16BQS(vk, publicKsum, nil)
	return sys, err
}

// SynthesizeGroth16Witness builds the exact Boolean witness vector solving
// CompileGroth16Verifier(vk, publicKsum) from a valid BN254 Groth16 proof.
func SynthesizeGroth16Witness(vk Groth16VK, publicKsum bn254.G1Affine, proof Groth16Proof) (*System, []bool, error) {
	return buildGroth16BQS(vk, publicKsum, &proof)
}
