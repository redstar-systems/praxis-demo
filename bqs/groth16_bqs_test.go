package bqs

import (
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestFpE2E12BQSArithmeticAndSoundness(t *testing.T) {
	var a, bVal, prod bn254.E12
	_, _ = a.SetRandom()
	_, _ = bVal.SetRandom()
	prod.Mul(&a, &bVal)

	fb := NewFpBuilder(true)
	va := fb.NewE12Var(a)
	vb := fb.NewE12Var(bVal)
	vc := fb.E12Mul(va, vb)

	// Verify E12Square matches gnark-crypto bit-for-bit.
	var wantSq bn254.E12
	wantSq.Square(&a)
	gotSq := fb.E12Square(va)
	for i, wCoord := range getE12Coords(&wantSq) {
		if gotSq.C[i].Val.Cmp(wCoord) != 0 {
			t.Fatalf("E12Square coord %d mismatch", i)
		}
	}

	// Verify sparse 034*034 batched multiplication (with deferred C1.B0/C1.B1 sums) matches E12.Mul.
	var c3, c4, d3, d4 bn254.E2
	_, _ = c3.SetRandom()
	_, _ = c4.SetRandom()
	_, _ = d3.SetRandom()
	_, _ = d4.SetRandom()
	var l1, l2, wantPairProd, wantMulPair bn254.E12
	l1.C0.B0.A0.SetOne()
	l1.C1.B0.Set(&c3)
	l1.C1.B1.Set(&c4)
	l2.C0.B0.A0.SetOne()
	l2.C1.B0.Set(&d3)
	l2.C1.B1.Set(&d4)
	wantPairProd.Mul(&l1, &l2)
	wantMulPair.Mul(&a, &wantPairProd)

	pairExpr := fb.E12Mul034By034Expr(fb.NewE2Var(c3), fb.NewE2Var(c4), fb.NewE2Var(d3), fb.NewE2Var(d4))
	gotMulPair := fb.E12MulExpr(e12ToExpr(va), pairExpr)
	for i, wCoord := range getE12Coords(&wantMulPair) {
		if gotMulPair.C[i].Val.Cmp(wCoord) != 0 {
			t.Fatalf("E12Mul034By034Expr coord %d mismatch", i)
		}
	}

	// Verify Frobenius1, 2, 3 match gnark-crypto bit-for-bit.
	var wantF1, wantF2, wantF3 bn254.E12
	wantF1.Frobenius(&a)
	wantF2.FrobeniusSquare(&a)
	wantF3.FrobeniusCube(&a)
	gotF1 := fb.E12FrobeniusMap(va, e12Frob1Mat)
	gotF2 := fb.E12FrobeniusMap(va, e12Frob2Mat)
	gotF3 := fb.E12FrobeniusMap(va, e12Frob3Mat)

	for i, wCoord := range getE12Coords(&prod) {
		if vc.C[i].Val.Cmp(wCoord) != 0 {
			t.Fatalf("E12Mul coord %d mismatch", i)
		}
	}
	for i, wCoord := range getE12Coords(&wantF1) {
		if gotF1.C[i].Val.Cmp(wCoord) != 0 {
			t.Fatalf("Frob1 coord %d mismatch", i)
		}
	}
	for i, wCoord := range getE12Coords(&wantF2) {
		if gotF2.C[i].Val.Cmp(wCoord) != 0 {
			t.Fatalf("Frob2 coord %d mismatch", i)
		}
	}
	for i, wCoord := range getE12Coords(&wantF3) {
		if gotF3.C[i].Val.Cmp(wCoord) != 0 {
			t.Fatalf("Frob3 coord %d mismatch", i)
		}
	}

	// Verify 2-constraint CRT(2^162, q) linear path via FpNeg and E2AssertEqual.
	negA0 := fb.FpNeg(va.C[0])
	negNegA0 := fb.FpNeg(negA0)
	fb.E2AssertEqual(E2Var{A0: va.C[0], A1: va.C[1]}, E2Var{A0: negNegA0, A1: va.C[1]})

	// Verify G1 and G2 curve checks (including fused G2 twist check and AssertG1OnCurveWithSquares).
	_, _, g1, g2 := bn254.Generators()
	var p1 bn254.G1Affine
	var q2 bn254.G2Affine
	p1.ScalarMultiplication(&g1, big.NewInt(1337))
	q2.ScalarMultiplication(&g2, big.NewInt(4242))
	fb.AssertG1OnCurve(fb.NewG1Var(p1))
	fb.AssertG1OnCurveWithSquares(fb.NewG1Var(p1))
	fb.AssertG2OnTwist(fb.NewG2Var(q2))

	sys, err := fb.System()
	if err != nil {
		t.Fatal(err)
	}
	if !sys.IsWitness(fb.W) {
		t.Fatalf("expected valid witness for E12 + Frobenius + G1/G2 BQS")
	}

	// Soundness: flipping bits in operand, quotient, and carry regions must invalidate the BQS.
	for _, idx := range []int{1, 128, 255, sys.N / 2, sys.N} {
		badW := append([]bool(nil), fb.W...)
		badW[idx] = !badW[idx]
		if sys.IsWitness(badW) {
			t.Fatalf("SECURITY FAILURE: 1-bit flip at witness[%d] still satisfied BQS!", idx)
		}
	}
	t.Logf("Fp/E2/E12/G1/G2 BQS PASS: N=%d constraints=%d Fmax=%d", sys.N, len(sys.Constraints), sys.Fmax())
}

func makeValidGroth16Instance(alphaU, betaU, gammaU, deltaU, kSumU, krsU, arU uint64) (Groth16VK, bn254.G1Affine, Groth16Proof) {
	_, _, g1, g2 := bn254.Generators()

	var alpha, beta, gamma, delta, kSumSc, krsSc, arSc fr.Element
	alpha.SetUint64(alphaU)
	beta.SetUint64(betaU)
	gamma.SetUint64(gammaU)
	delta.SetUint64(deltaU)
	kSumSc.SetUint64(kSumU)
	krsSc.SetUint64(krsU)
	arSc.SetUint64(arU)

	// bs = (alpha*beta + kSum*gamma + krs*delta) / ar  mod r
	var rhs, tmp, bsSc fr.Element
	rhs.Mul(&alpha, &beta)
	tmp.Mul(&kSumSc, &gamma)
	rhs.Add(&rhs, &tmp)
	tmp.Mul(&krsSc, &delta)
	rhs.Add(&rhs, &tmp)
	bsSc.Div(&rhs, &arSc)

	var vk Groth16VK
	vk.AlphaNeg.ScalarMultiplication(&g1, alpha.BigInt(new(big.Int)))
	vk.AlphaNeg.Neg(&vk.AlphaNeg)
	vk.Beta.ScalarMultiplication(&g2, beta.BigInt(new(big.Int)))
	vk.GammaNeg.ScalarMultiplication(&g2, gamma.BigInt(new(big.Int)))
	vk.GammaNeg.Neg(&vk.GammaNeg)
	vk.DeltaNeg.ScalarMultiplication(&g2, delta.BigInt(new(big.Int)))
	vk.DeltaNeg.Neg(&vk.DeltaNeg)

	var pubKsum bn254.G1Affine
	pubKsum.ScalarMultiplication(&g1, kSumSc.BigInt(new(big.Int)))

	var proof Groth16Proof
	proof.Ar.ScalarMultiplication(&g1, arSc.BigInt(new(big.Int)))
	proof.Bs.ScalarMultiplication(&g2, bsSc.BigInt(new(big.Int)))
	proof.Krs.ScalarMultiplication(&g1, krsSc.BigInt(new(big.Int)))
	return vk, pubKsum, proof
}

func writeFpBits(w []bool, startIdx int, v *big.Int) {
	m := new(big.Int).Mod(v, bn254P)
	for i := 0; i < fpTotalBit; i++ {
		w[startIdx+i] = m.Bit(i) == 1
	}
}

// TestBN254Groth16VerifierBQSRealProof compiles a complete BN254 Groth16 pairing verifier
// into a bqs.System over F_q, synthesizes a valid proof witness, proves encSys.IsWitness(w)==true,
// logs exact before-vs-after optimization metrics, and verifies all forgery rejections.
func TestBN254Groth16VerifierBQSRealProof(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()
	vk, pubKsum, proof := makeValidGroth16Instance(1111111, 2222222, 3333333, 4444444, 5555555, 6666666, 7777777)

	// Sanity check pairing equation directly via gnark-crypto.
	okPair, err := bn254.PairingCheck(
		[]bn254.G1Affine{proof.Ar, proof.Krs, pubKsum, vk.AlphaNeg},
		[]bn254.G2Affine{proof.Bs, vk.DeltaNeg, vk.GammaNeg, vk.Beta},
	)
	if err != nil || !okPair {
		t.Fatalf("sanity PairingCheck failed: ok=%v err=%v", okPair, err)
	}

	// 1. Compile verifier BQS without proof (encryptor side).
	t0 := time.Now()
	encSys, err := CompileGroth16Verifier(vk, pubKsum)
	if err != nil {
		t.Fatalf("CompileGroth16Verifier: %v", err)
	}
	compileDur := time.Since(t0)

	// 2. Synthesize exact Boolean witness from valid proof (claimer side).
	t1 := time.Now()
	witSys, w, err := SynthesizeGroth16Witness(vk, pubKsum, proof)
	if err != nil {
		t.Fatalf("SynthesizeGroth16Witness: %v", err)
	}
	synthDur := time.Since(t1)

	if encSys.N != witSys.N || len(encSys.Constraints) != len(witSys.Constraints) {
		t.Fatalf("compile vs synth shape mismatch: (%d,%d) vs (%d,%d)",
			encSys.N, len(encSys.Constraints), witSys.N, len(witSys.Constraints))
	}

	// 3. Verify EVERY SINGLE BQS constraint of the entire BN254 optimal Ate pairing.
	t2 := time.Now()
	if !encSys.IsWitness(w) {
		t.Fatalf("valid Groth16 proof witness FAILED encSys.IsWitness(w)!")
	}
	checkDur := time.Since(t2)

	fmax := encSys.Fmax()
	nu := 2
	for nu <= fmax {
		nu *= 2
	}

	// Exact baseline metrics (pre-optimization 4x68-bit unbatched compiler):
	//   N=3,064,950 | nc=13,884 | Fmax=154 (nu=256) | compile~2135ms | synth~2175ms | check~426ms
	const (
		baseN    = 3064950
		baseNC   = 13884
		baseFmax = 154
		baseNu   = 256
	)
	t.Logf("BN254 GROTH16 BQS BEFORE: N=%d | nc=%d | Fmax=%d (nu=%d) | D=%d | compile~2135ms | synth~2175ms | check~426ms",
		baseN, baseNC, baseFmax, baseNu, baseN+2+baseNu*baseNC)
	t.Logf("BN254 GROTH16 BQS AFTER:  N=%d (-%.1f%%) | nc=%d (-%.1f%%) | Fmax=%d (-%.1f%%, nu=%d) | D=%d (-%.1f%%) | compile=%v | synth=%v | check=%v",
		encSys.N, 100*float64(baseN-encSys.N)/float64(baseN),
		len(encSys.Constraints), 100*float64(baseNC-len(encSys.Constraints))/float64(baseNC),
		fmax, 100*float64(baseFmax-fmax)/float64(baseFmax), nu,
		encSys.N+2+nu*len(encSys.Constraints),
		100*float64((baseN+2+baseNu*baseNC)-(encSys.N+2+nu*len(encSys.Constraints)))/float64(baseN+2+baseNu*baseNC),
		compileDur.Round(time.Millisecond), synthDur.Round(time.Millisecond), checkDur.Round(time.Millisecond))

	// Regression guardrails confirming concrete reductions.
	if encSys.N >= 2500000 {
		t.Fatalf("expected optimized N < 2,500,000, got %d", encSys.N)
	}
	if len(encSys.Constraints) >= 12000 {
		t.Fatalf("expected optimized nc < 12,000, got %d", len(encSys.Constraints))
	}
	if fmax > 63 {
		t.Fatalf("expected optimized Fmax <= 63 (nu=64), got %d", fmax)
	}

	// 4. Verify a second distinct valid proof (different Ar/Bs/Krs randomizers for the SAME vk & pubKsum)
	// also satisfies the exact same compiled encSys.
	_, _, proofAlt := makeValidGroth16Instance(1111111, 2222222, 3333333, 4444444, 5555555, 8888888, 9999991)
	_, wAlt, err := SynthesizeGroth16Witness(vk, pubKsum, proofAlt)
	if err != nil {
		t.Fatalf("SynthesizeGroth16Witness(proofAlt): %v", err)
	}
	if !encSys.IsWitness(wAlt) {
		t.Fatalf("second valid Groth16 proof FAILED encSys.IsWitness(wAlt)!")
	}

	// 5. Forgery & Soundness Checks:
	// 5a. Tampered proof.Ar (valid G1 point, invalid pairing): synthesizer rejects AND spliced witness fails encSys!
	forgedAr := proof
	forgedAr.Ar.Add(&forgedAr.Ar, &g1)
	if _, _, err := SynthesizeGroth16Witness(vk, pubKsum, forgedAr); err == nil {
		t.Fatalf("SECURITY FAILURE: SynthesizeGroth16Witness accepted tampered proof.Ar!")
	}
	badArSplice := append([]bool(nil), w...)
	writeFpBits(badArSplice, 1, forgedAr.Ar.X.BigInt(new(big.Int)))
	writeFpBits(badArSplice, 1+fpTotalBit, forgedAr.Ar.Y.BigInt(new(big.Int)))
	if encSys.IsWitness(badArSplice) {
		t.Fatalf("SECURITY FAILURE: spliced tampered proof.Ar satisfied encSys!")
	}

	// 5b. Tampered proof.Krs (valid G1 point, invalid pairing): synthesizer rejects AND spliced witness fails encSys!
	forgedKrs := proof
	forgedKrs.Krs.Add(&forgedKrs.Krs, &g1)
	if _, _, err := SynthesizeGroth16Witness(vk, pubKsum, forgedKrs); err == nil {
		t.Fatalf("SECURITY FAILURE: SynthesizeGroth16Witness accepted tampered proof.Krs!")
	}
	krsStart := 1 + 2*fpTotalBit // after Ar (X, Y)
	badKrsSplice := append([]bool(nil), w...)
	writeFpBits(badKrsSplice, krsStart, forgedKrs.Krs.X.BigInt(new(big.Int)))
	writeFpBits(badKrsSplice, krsStart+fpTotalBit, forgedKrs.Krs.Y.BigInt(new(big.Int)))
	if encSys.IsWitness(badKrsSplice) {
		t.Fatalf("SECURITY FAILURE: spliced tampered proof.Krs satisfied encSys!")
	}

	// 5c. Tampered proof.Bs (valid G2 point, invalid pairing): synthesizer rejects AND spliced witness fails encSys!
	forgedBs := proof
	forgedBs.Bs.Add(&forgedBs.Bs, &g2)
	if _, _, err := SynthesizeGroth16Witness(vk, pubKsum, forgedBs); err == nil {
		t.Fatalf("SECURITY FAILURE: SynthesizeGroth16Witness accepted tampered proof.Bs!")
	}
	bsStart := 1 + 4*fpTotalBit // after Ar (2 Fp) and Krs (2 Fp)
	badBsSplice := append([]bool(nil), w...)
	writeFpBits(badBsSplice, bsStart, forgedBs.Bs.X.A0.BigInt(new(big.Int)))
	writeFpBits(badBsSplice, bsStart+fpTotalBit, forgedBs.Bs.X.A1.BigInt(new(big.Int)))
	writeFpBits(badBsSplice, bsStart+2*fpTotalBit, forgedBs.Bs.Y.A0.BigInt(new(big.Int)))
	writeFpBits(badBsSplice, bsStart+3*fpTotalBit, forgedBs.Bs.Y.A1.BigInt(new(big.Int)))
	if encSys.IsWitness(badBsSplice) {
		t.Fatalf("SECURITY FAILURE: spliced tampered proof.Bs satisfied encSys!")
	}

	// 5d. Wrong public input pubKsum:
	// - Valid proof witness w for pubKsum MUST fail verifier compiled for pubKsum2.
	// - Valid proof witness w2 (internally consistent across all curve + Miller-loop constraints)
	//   for pubKsum2 MUST fail encSys compiled for pubKsum.
	_, pubKsum2, proof2 := makeValidGroth16Instance(1111111, 2222222, 3333333, 4444444, 9999999, 6666666, 7777777)
	otherSys, err := CompileGroth16Verifier(vk, pubKsum2)
	if err != nil {
		t.Fatalf("CompileGroth16Verifier(other): %v", err)
	}
	if otherSys.IsWitness(w) {
		t.Fatalf("SECURITY FAILURE: proof for pubKsum satisfied verifier compiled for pubKsum2!")
	}
	_, w2, err := SynthesizeGroth16Witness(vk, pubKsum2, proof2)
	if err != nil {
		t.Fatalf("SynthesizeGroth16Witness(proof2): %v", err)
	}
	if !otherSys.IsWitness(w2) {
		t.Fatalf("expected valid proof2 to satisfy otherSys")
	}
	if encSys.IsWitness(w2) {
		t.Fatalf("SECURITY FAILURE: valid proof2 for pubKsum2 satisfied encSys for pubKsum!")
	}

	// 5e. Single-bit flipped witness entries across constant slot, Ar, Krs, Bs, Miller loop, and final check.
	flipIndices := []struct {
		name string
		idx  int
	}{
		{"const_slot", 0},
		{"proof.Ar.X", 1},
		{"proof.Ar.Y", 1 + fpTotalBit},
		{"proof.Krs.X", krsStart},
		{"proof.Krs.Y", krsStart + fpTotalBit},
		{"proof.Bs.X.A0", bsStart},
		{"proof.Bs.Y.A1", bsStart + 3*fpTotalBit},
		{"miller_loop_mid", encSys.N / 2},
		{"final_check_tail", encSys.N - 7},
		{"last_unknown", encSys.N},
	}
	for _, tc := range flipIndices {
		badW := append([]bool(nil), w...)
		badW[tc.idx] = !badW[tc.idx]
		if encSys.IsWitness(badW) {
			t.Fatalf("SECURITY FAILURE: 1-bit flip at %s (w[%d]) satisfied Groth16 verifier BQS!", tc.name, tc.idx)
		}
	}
}
