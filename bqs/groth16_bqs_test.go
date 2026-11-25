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

	// Verify G1 and G2 curve checks.
	_, _, g1, g2 := bn254.Generators()
	var p1 bn254.G1Affine
	var q2 bn254.G2Affine
	p1.ScalarMultiplication(&g1, big.NewInt(1337))
	q2.ScalarMultiplication(&g2, big.NewInt(4242))
	fb.AssertG1OnCurve(fb.NewG1Var(p1))
	fb.AssertG2OnTwist(fb.NewG2Var(q2))

	sys, err := fb.System()
	if err != nil {
		t.Fatal(err)
	}
	if !sys.IsWitness(fb.W) {
		t.Fatalf("expected valid witness for E12 + Frobenius + G1/G2 BQS")
	}

	// Soundness: flipping any bit of a must invalidate the BQS!
	badW := append([]bool(nil), fb.W...)
	badW[1] = !badW[1]
	if sys.IsWitness(badW) {
		t.Fatalf("SECURITY FAILURE: 1-bit flipped E12 operand still satisfied BQS!")
	}
	t.Logf("Fp/E2/E12/G1/G2 BQS PASS: N=%d constraints=%d Fmax=%d", sys.N, len(sys.Constraints), sys.Fmax())
}

// TestBN254Groth16VerifierBQSRealProof compiles a complete BN254 Groth16 pairing verifier
// into a bqs.System over F_q, synthesizes a valid proof witness, proves sys.IsWitness(w)==true,
// and asserts forged proofs / substituted public inputs fail!
func TestBN254Groth16VerifierBQSRealProof(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()

	// Construct a cryptographically valid Groth16 trapdoor instance:
	//   alpha*beta + kSum*gamma + krs*delta == ar*bs  (mod r)
	// => e(Ar, Bs) * e(Krs, -delta) * e(Ksum, -gamma) * e(-alpha, beta) == 1.
	var alpha, beta, gamma, delta, kSumSc, krsSc, arSc fr.Element
	alpha.SetUint64(1111111)
	beta.SetUint64(2222222)
	gamma.SetUint64(3333333)
	delta.SetUint64(4444444)
	kSumSc.SetUint64(5555555)
	krsSc.SetUint64(6666666)
	arSc.SetUint64(7777777)

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

	// Sanity check pairing equation directly via gnark-crypto.
	okPair, err := bn254.PairingCheck(
		[]bn254.G1Affine{proof.Ar, proof.Krs, pubKsum, vk.AlphaNeg},
		[]bn254.G2Affine{proof.Bs, vk.DeltaNeg, vk.GammaNeg, vk.Beta},
	)
	if err != nil || !okPair {
		t.Fatalf("sanity PairingCheck failed: ok=%v err=%v", okPair, err)
	}

	// 1. Compile verifier BQS without proof (encryptor side!).
	t0 := time.Now()
	encSys, err := CompileGroth16Verifier(vk, pubKsum)
	if err != nil {
		t.Fatalf("CompileGroth16Verifier: %v", err)
	}
	compileDur := time.Since(t0)

	// 2. Synthesize exact Boolean witness from valid proof (claimer side!).
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

	// 3. Verify EVERY SINGLE BQS constraint of the entire BN254 optimal Ate pairing!
	t2 := time.Now()
	if !encSys.IsWitness(w) {
		t.Fatalf("valid Groth16 proof witness FAILED encSys.IsWitness(w)!")
	}
	checkDur := time.Since(t2)
	t.Logf("BN254 GROTH16 VERIFIER BQS PASS: N=%d unknowns | nc=%d constraints | Fmax=%d | compile=%v | synth=%v | check=%v",
		encSys.N, len(encSys.Constraints), encSys.Fmax(), compileDur, synthDur, checkDur)

	// 4. Forgery checks:
	// 4a. Flipping 1 bit in proof.Ar (first G1 coord) MUST fail encSys!
	badArW := append([]bool(nil), w...)
	badArW[1] = !badArW[1]
	if encSys.IsWitness(badArW) {
		t.Fatalf("SECURITY FAILURE: tampered proof.Ar satisfied Groth16 verifier BQS!")
	}

	// 4b. Valid proof for pubKsum MUST FAIL verifier compiled for a DIFFERENT public input pubKsum2!
	var pubKsum2 bn254.G1Affine
	pubKsum2.ScalarMultiplication(&g1, big.NewInt(9999999))
	otherSys, err := CompileGroth16Verifier(vk, pubKsum2)
	if err != nil {
		t.Fatalf("CompileGroth16Verifier(other): %v", err)
	}
	if otherSys.IsWitness(w) {
		t.Fatalf("SECURITY FAILURE: proof for pubKsum satisfied verifier compiled for pubKsum2!")
	}
}
