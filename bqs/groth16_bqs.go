package bqs

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
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

// g2DoubleStepBQS computes 2*accQ and its affine tangent line (R0, R1) in BQS constraints,
// matching gnark-crypto/ecc/bn254/pairing.go:1030 bit-for-bit.
func g2DoubleStepBQS(b *FpBuilder, accQ G2Var, hostQ *bn254.G2Affine) (G2Var, LineAffVar) {
	var hostLambda, hostXr, hostYr, hostR1 bn254.E2
	if b.synth {
		var n, d bn254.E2
		n.Square(&hostQ.X)
		hostLambda.Double(&n).Add(&hostLambda, &n)
		d.Double(&hostQ.Y)
		hostLambda.Div(&hostLambda, &d)
		hostXr.Square(&hostLambda).Sub(&hostXr, &hostQ.X).Sub(&hostXr, &hostQ.X)
		hostYr.Sub(&hostQ.X, &hostXr).Mul(&hostYr, &hostLambda).Sub(&hostYr, &hostQ.Y)
		hostR1.Mul(&hostLambda, &hostQ.X).Sub(&hostR1, &hostQ.Y)
		hostQ.X.Set(&hostXr)
		hostQ.Y.Set(&hostYr)
	}
	lam := b.NewE2Var(hostLambda)
	xr := b.NewE2Var(hostXr)
	yr := b.NewE2Var(hostYr)
	r1 := b.NewE2Var(hostR1)

	// 1. 2 * y * lam == 3 * x^2  (in E2: 2 F_p constraints!)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: accQ.Y.A0, B: lam.A0},
		{Coeff: -2, A: accQ.Y.A1, B: lam.A1},
		{Coeff: -3, A: accQ.X.A0, B: accQ.X.A0},
		{Coeff: 3, A: accQ.X.A1, B: accQ.X.A1},
	}, nil, nil, b.ConstFp(big.NewInt(0)))
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: accQ.Y.A0, B: lam.A1},
		{Coeff: 2, A: accQ.Y.A1, B: lam.A0},
		{Coeff: -6, A: accQ.X.A0, B: accQ.X.A1},
	}, nil, nil, b.ConstFp(big.NewInt(0)))

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

	// 4. r1 == lam * x - y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A0},
		{Coeff: -1, A: lam.A1, B: accQ.X.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A0}}, nil, r1.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A1},
		{Coeff: 1, A: lam.A1, B: accQ.X.A0},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A1}}, nil, r1.A1)

	return G2Var{X: xr, Y: yr}, LineAffVar{R0: lam, R1: r1}
}

// g2AddStepBQS computes accQ + a and its affine chord line (R0, R1) in BQS constraints,
// matching gnark-crypto/ecc/bn254/pairing.go:1058 bit-for-bit.
func g2AddStepBQS(b *FpBuilder, accQ, a G2Var, hostQ *bn254.G2Affine, hostA bn254.G2Affine) (G2Var, LineAffVar) {
	var hostLam, hostXr, hostYr, hostR1 bn254.E2
	if b.synth {
		var n, d bn254.E2
		n.Sub(&hostA.Y, &hostQ.Y)
		d.Sub(&hostA.X, &hostQ.X)
		hostLam.Div(&n, &d)
		hostXr.Square(&hostLam).Sub(&hostXr, &hostQ.X).Sub(&hostXr, &hostA.X)
		hostYr.Sub(&hostQ.X, &hostXr).Mul(&hostYr, &hostLam).Sub(&hostYr, &hostQ.Y)
		hostR1.Mul(&hostLam, &hostQ.X).Sub(&hostR1, &hostQ.Y)
		hostQ.X.Set(&hostXr)
		hostQ.Y.Set(&hostYr)
	}
	lam := b.NewE2Var(hostLam)
	xr := b.NewE2Var(hostXr)
	yr := b.NewE2Var(hostYr)
	r1 := b.NewE2Var(hostR1)

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

	// 4. r1 == lam * p.X - p.Y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A0},
		{Coeff: -1, A: lam.A1, B: accQ.X.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A0}}, nil, r1.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: lam.A0, B: accQ.X.A1},
		{Coeff: 1, A: lam.A1, B: accQ.X.A0},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A1}}, nil, r1.A1)

	return G2Var{X: xr, Y: yr}, LineAffVar{R0: lam, R1: r1}
}

// g2DoubleAndAddStepBQS computes 2*accQ + a and both affine chord lines (l1, l2),
// matching gnark-crypto/ecc/bn254/pairing.go:1084 bit-for-bit.
func g2DoubleAndAddStepBQS(b *FpBuilder, accQ, a G2Var, hostQ *bn254.G2Affine, hostA bn254.G2Affine) (G2Var, LineAffVar, LineAffVar) {
	var hostL1, hostX3, hostR11, hostL2, hostX4, hostY4, hostR12 bn254.E2
	if b.synth {
		var A, B, A2, B2, t, U, invA, invU bn254.E2
		A.Sub(&hostQ.X, &hostA.X)
		B.Sub(&hostQ.Y, &hostA.Y)
		A2.Square(&A)
		B2.Square(&B)
		t.Double(&hostQ.X).Add(&t, &hostA.X)
		U.Mul(&t, &A2).Sub(&B2, &U)
		invA.Inverse(&A)
		invU.Inverse(&U)
		hostL1.Mul(&B, &invA)
		hostX3.Square(&hostL1).Sub(&hostX3, &hostQ.X).Sub(&hostX3, &hostA.X)
		hostR11.Mul(&hostL1, &hostQ.X).Sub(&hostR11, &hostQ.Y)
		hostL2.Double(&hostQ.Y).Mul(&hostL2, &A2).Mul(&hostL2, &invU).Add(&hostL2, &hostL1).Neg(&hostL2)
		hostX4.Square(&hostL2).Sub(&hostX4, &hostQ.X).Sub(&hostX4, &hostX3)
		hostY4.Sub(&hostQ.X, &hostX4).Mul(&hostY4, &hostL2).Sub(&hostY4, &hostQ.Y)
		hostR12.Mul(&hostL2, &hostQ.X).Sub(&hostR12, &hostQ.Y)
		hostQ.X.Set(&hostX4)
		hostQ.Y.Set(&hostY4)
	}
	l1 := b.NewE2Var(hostL1)
	x3 := b.NewE2Var(hostX3)
	r11 := b.NewE2Var(hostR11)
	l2 := b.NewE2Var(hostL2)
	x4 := b.NewE2Var(hostX4)
	y4 := b.NewE2Var(hostY4)
	r12 := b.NewE2Var(hostR12)

	// 1. l1 * (p.X - a.X) == p.Y - a.Y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l1.A0, B: accQ.X.A0},
		{Coeff: -1, A: l1.A1, B: accQ.X.A1},
		{Coeff: -1, A: l1.A0, B: a.X.A0},
		{Coeff: 1, A: l1.A1, B: a.X.A1},
	}, []FpLinTerm{{Coeff: 1, X: a.Y.A0}}, nil, accQ.Y.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l1.A0, B: accQ.X.A1},
		{Coeff: 1, A: l1.A1, B: accQ.X.A0},
		{Coeff: -1, A: l1.A0, B: a.X.A1},
		{Coeff: -1, A: l1.A1, B: a.X.A0},
	}, []FpLinTerm{{Coeff: 1, X: a.Y.A1}}, nil, accQ.Y.A1)

	// 2. x3 == l1^2 - p.X - a.X
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l1.A0, B: l1.A0},
		{Coeff: -1, A: l1.A1, B: l1.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A0}, {Coeff: -1, X: a.X.A0}}, nil, x3.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: l1.A0, B: l1.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A1}, {Coeff: -1, X: a.X.A1}}, nil, x3.A1)

	// 3. r11 == l1 * p.X - p.Y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l1.A0, B: accQ.X.A0},
		{Coeff: -1, A: l1.A1, B: accQ.X.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A0}}, nil, r11.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l1.A0, B: accQ.X.A1},
		{Coeff: 1, A: l1.A1, B: accQ.X.A0},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A1}}, nil, r11.A1)

	// 4. (l2 + l1) * (x3 - p.X) + 2*p.Y == 0
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: x3.A0},
		{Coeff: -1, A: l2.A1, B: x3.A1},
		{Coeff: 1, A: l1.A0, B: x3.A0},
		{Coeff: -1, A: l1.A1, B: x3.A1},
		{Coeff: -1, A: l2.A0, B: accQ.X.A0},
		{Coeff: 1, A: l2.A1, B: accQ.X.A1},
		{Coeff: -1, A: l1.A0, B: accQ.X.A0},
		{Coeff: 1, A: l1.A1, B: accQ.X.A1},
	}, []FpLinTerm{{Coeff: 2, X: accQ.Y.A0}}, nil, b.ConstFp(big.NewInt(0)))
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: x3.A1},
		{Coeff: 1, A: l2.A1, B: x3.A0},
		{Coeff: 1, A: l1.A0, B: x3.A1},
		{Coeff: 1, A: l1.A1, B: x3.A0},
		{Coeff: -1, A: l2.A0, B: accQ.X.A1},
		{Coeff: -1, A: l2.A1, B: accQ.X.A0},
		{Coeff: -1, A: l1.A0, B: accQ.X.A1},
		{Coeff: -1, A: l1.A1, B: accQ.X.A0},
	}, []FpLinTerm{{Coeff: 2, X: accQ.Y.A1}}, nil, b.ConstFp(big.NewInt(0)))

	// 5. x4 == l2^2 - p.X - x3
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: l2.A0},
		{Coeff: -1, A: l2.A1, B: l2.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A0}, {Coeff: -1, X: x3.A0}}, nil, x4.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 2, A: l2.A0, B: l2.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.X.A1}, {Coeff: -1, X: x3.A1}}, nil, x4.A1)

	// 6. y4 == l2 * (p.X - x4) - p.Y
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

	// 7. r12 == l2 * p.X - p.Y
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: accQ.X.A0},
		{Coeff: -1, A: l2.A1, B: accQ.X.A1},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A0}}, nil, r12.A0)
	b.AssertQuadModP([]FpQuadTerm{
		{Coeff: 1, A: l2.A0, B: accQ.X.A1},
		{Coeff: 1, A: l2.A1, B: accQ.X.A0},
	}, []FpLinTerm{{Coeff: -1, X: accQ.Y.A1}}, nil, r12.A1)

	return G2Var{X: x4, Y: y4}, LineAffVar{R0: l1, R1: r11}, LineAffVar{R0: l2, R1: r12}
}

// buildGroth16BQS builds the complete BN254 Groth16 verifier BQS for a fixed verifying key
// and fixed public input sum K_sum. When proof != nil, simultaneously synthesizes the exact
// Boolean witness vector w []bool.
//
// Proved statement:
//   - Ar, Krs lie on BN254 G1 (y^2 = x^3 + 3)
//   - Bs lies on BN254 G2 twist (y^2 = x^3 + 3/(9+u))
//   - e(Ar, Bs) * e(Krs, -delta) * e(Ksum, -gamma) * e(-alpha, beta) == 1 in G_T
//     verified via Novakovic-Eagen (ePrint 2024/640) folded Miller loop + cubic non-residue
//     witness w_i in F_{p^6} + non-zero invertibility c * c^{-1} == 1.
func buildGroth16BQS(vk Groth16VK, publicKsum bn254.G1Affine, proof *Groth16Proof) (*System, []bool, error) {
	synth := proof != nil
	b := NewFpBuilder(synth)

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

	var hostAr, hostKrs bn254.G1Affine
	var hostBs bn254.G2Affine
	var hostResWitnessInv, hostResWitness, hostWi bn254.E12
	if synth {
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
		hostResWitnessInv, hostWi = ComputeBN254FinalExpWitness(&totalML)
		hostResWitness.Inverse(&hostResWitnessInv)
	}

	// Allocate proof variables & enforce curve equations (rules out infinity (0,0)).
	ar := b.NewG1Var(hostAr)
	krs := b.NewG1Var(hostKrs)
	bs := b.NewG2Var(hostBs)
	b.AssertG1OnCurve(ar)
	b.AssertG1OnCurve(krs)
	b.AssertG2OnTwist(bs)

	// Precompute affine evaluation factors (-x/y, 1/y) for Ar and Krs.
	arYInv := b.FpInv(ar.Y)
	arXNegOverY := b.FpNeg(b.FpMul(ar.X, arYInv))
	krsYInv := b.FpInv(krs.Y)
	krsXNegOverY := b.FpNeg(b.FpMul(krs.X, krsYInv))

	// Allocate Novakovic-Eagen residue witness c^{-1}, c (with c * c^{-1} == 1 ruling out 0==0)
	// and cubic non-residue power w_i constrained to F_{p^6} (C1 == 0!).
	cInv := b.NewE12Var(hostResWitnessInv)
	cVal := b.NewE12Var(hostResWitness)
	var oneE12 bn254.E12
	oneE12.SetOne()
	b.AssertE12Mul(cInv, cVal, b.ConstE12(oneE12))

	zeroFp := b.ConstFp(big.NewInt(0))
	var wiCoords [12]*big.Int
	if synth {
		wiCoords = getE12Coords(&hostWi)
	}
	wi := E12Var{
		C: [12]FpVar{
			b.NewFpVar(wiCoords[0]), b.NewFpVar(wiCoords[1]),
			b.NewFpVar(wiCoords[2]), b.NewFpVar(wiCoords[3]),
			b.NewFpVar(wiCoords[4]), b.NewFpVar(wiCoords[5]),
			zeroFp, zeroFp, zeroFp, zeroFp, zeroFp, zeroFp, // strictly in F_{p^6}!
		},
	}

	// Build affine line evaluations for variable Bs in-BQS and fold cInv into the 6x+2 Miller loop!
	negBs := G2Var{
		X: bs.X,
		Y: E2Var{A0: b.FpNeg(bs.Y.A0), A1: b.FpNeg(bs.Y.A1)},
	}
	var hostAccQ, hostNegBs bn254.G2Affine
	if synth {
		hostAccQ = hostBs
		hostNegBs.Neg(&hostBs)
	}
	accQ := bs
	res := cInv // LoopCounter[65] = 1 -> res starts at c^{-1}

	evalLine := func(line LineAffVar, xNegY, yInv FpVar) (E2Var, E2Var) {
		return b.E2MulByFp(line.R0, xNegY), b.E2MulByFp(line.R1, yInv)
	}
	constLine := func(l bn254.LineEvaluationAff) LineAffVar {
		return LineAffVar{R0: b.ConstE2(l.R0), R1: b.ConstE2(l.R1)}
	}

	for i := len(bn254.LoopCounter) - 2; i >= 0; i-- {
		res = b.E12Square(res)
		bit := bn254.LoopCounter[i]
		switch bit {
		case 0:
			var lBs LineAffVar
			accQ, lBs = g2DoubleStepBQS(b, accQ, &hostAccQ)
			c3, c4 := evalLine(lBs, arXNegOverY, arYInv)
			res = b.E12MulBy34(res, c3, c4)
			d3, d4 := evalLine(constLine(linesDelta[0][i]), krsXNegOverY, krsYInv)
			res = b.E12MulBy34(res, d3, d4)
		case 1:
			res = b.E12Mul(res, cInv)
			var lBs1, lBs2 LineAffVar
			accQ, lBs1, lBs2 = g2DoubleAndAddStepBQS(b, accQ, bs, &hostAccQ, hostBs)
			c3, c4 := evalLine(lBs1, arXNegOverY, arYInv)
			res = b.E12MulBy34(res, c3, c4)
			c3, c4 = evalLine(lBs2, arXNegOverY, arYInv)
			res = b.E12MulBy34(res, c3, c4)
			d3, d4 := evalLine(constLine(linesDelta[0][i]), krsXNegOverY, krsYInv)
			res = b.E12MulBy34(res, d3, d4)
			d3, d4 = evalLine(constLine(linesDelta[1][i]), krsXNegOverY, krsYInv)
			res = b.E12MulBy34(res, d3, d4)
		case -1:
			res = b.E12Mul(res, cVal)
			var lBs1, lBs2 LineAffVar
			accQ, lBs1, lBs2 = g2DoubleAndAddStepBQS(b, accQ, negBs, &hostAccQ, hostNegBs)
			c3, c4 := evalLine(lBs1, arXNegOverY, arYInv)
			res = b.E12MulBy34(res, c3, c4)
			c3, c4 = evalLine(lBs2, arXNegOverY, arYInv)
			res = b.E12MulBy34(res, c3, c4)
			d3, d4 := evalLine(constLine(linesDelta[0][i]), krsXNegOverY, krsYInv)
			res = b.E12MulBy34(res, d3, d4)
			d3, d4 = evalLine(constLine(linesDelta[1][i]), krsXNegOverY, krsYInv)
			res = b.E12MulBy34(res, d3, d4)
		}
	}

	// Final Frobenius lines: Q1 = phi(Bs) and Q2 = -psi(Bs) (matches PrecomputeLines lines 859-866).
	phiBs := G2Var{
		X: b.E2LinearMap(bs.X, g2PhiXMat),
		Y: b.E2LinearMap(bs.Y, g2PhiYMat),
	}
	psiBs := G2Var{
		X: b.E2LinearMap(bs.X, g2PsiXMat),
		Y: b.E2LinearMap(bs.Y, g2PsiYMat),
	}
	var hostPhiBs, hostPsiBs bn254.G2Affine
	if synth {
		hostPhiBs.X.Conjugate(&hostBs.X).MulByNonResidue1Power2(&hostPhiBs.X)
		hostPhiBs.Y.Conjugate(&hostBs.Y).MulByNonResidue1Power3(&hostPhiBs.Y)
		hostPsiBs.X.MulByNonResidue2Power2(&hostBs.X)
		hostPsiBs.Y.MulByNonResidue2Power3(&hostBs.Y).Neg(&hostPsiBs.Y)
	}
	var lPhi, lPsi LineAffVar
	accQ, lPhi = g2AddStepBQS(b, accQ, phiBs, &hostAccQ, hostPhiBs)
	_, lPsi = g2AddStepBQS(b, accQ, psiBs, &hostAccQ, hostPsiBs)

	c3, c4 := evalLine(lPhi, arXNegOverY, arYInv)
	res = b.E12MulBy34(res, c3, c4)
	c3, c4 = evalLine(lPsi, arXNegOverY, arYInv)
	res = b.E12MulBy34(res, c3, c4)
	d3, d4 := evalLine(constLine(linesDelta[1][65]), krsXNegOverY, krsYInv)
	res = b.E12MulBy34(res, d3, d4)
	d3, d4 = evalLine(constLine(linesDelta[0][65]), krsXNegOverY, krsYInv)
	res = b.E12MulBy34(res, d3, d4)

	// Multiply by constant fixedML = MillerLoop(Ksum, -gamma) * MillerLoop(-alpha, beta).
	res = b.E12Mul(res, b.ConstE12(fixedML))

	// Final Novakovic-Eagen check (division-free!):
	//   res * wi * (cInv)^(p^3) * (cInv)^p == (cInv)^(p^2)
	// Equivalent to: MillerLoop * wi * (cInv)^(6x+2 + p^3 - p^2 + p) == 1.
	frob1 := b.E12FrobeniusMap(cInv, e12Frob1Mat)
	frob2 := b.E12FrobeniusMap(cInv, e12Frob2Mat)
	frob3 := b.E12FrobeniusMap(cInv, e12Frob3Mat)

	t1 := b.E12Mul(res, wi)
	t2 := b.E12Mul(frob3, frob1)
	b.AssertE12Mul(t1, t2, frob2)

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
