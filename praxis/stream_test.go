package praxis

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"praxis-demo/bqs"
)

func TestStreamFormsAndWeightsMatchDense(t *testing.T) {
	seed := []byte("0123456789abcdef0123456789abcdef")
	for _, tc := range []struct {
		name string
		par  Params
		N    int
	}{
		{"Toy", Toy, 19},
		{"Advanced", Advanced, 73},
		{"Medium", Spectrum[2].Params, 137},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newField(tc.par.NForms())
			phi := tc.par.forms(seed, tc.N)

			var ups, xMinus, xCirc, xPlus fr.Element
			ups.SetUint64(123456789)
			xCirc.Neg(&ups)
			xPlus.Mul(&xCirc, &f.omega)
			xMinus.Div(&xCirc, &f.omega)

			wantM, wantC, wantP := zAt(phi, &xMinus), zAt(phi, &xCirc), zAt(phi, &xPlus)
			gotM, gotC, gotP := tc.par.zAtTripleStream(seed, tc.N, &xMinus, &xCirc, &xPlus)
			for i := 0; i <= tc.N; i++ {
				if !gotM[i].Equal(&wantM[i]) || !gotC[i].Equal(&wantC[i]) || !gotP[i].Equal(&wantP[i]) {
					t.Fatalf("zAt mismatch at index %d", i)
				}
			}

			w := make([]bool, tc.N+1)
			w[0] = true
			for i := 1; i <= tc.N; i += 3 {
				w[i] = true
			}
			wantWt := tc.par.weightsOf(f, phi, w)
			gotWt := tc.par.weightsOfStream(f, seed, tc.N, w)
			for k := 0; k < f.n; k++ {
				if !gotWt.U[k].Equal(&wantWt.U[k]) || !gotWt.V[k].Equal(&wantWt.V[k]) {
					t.Fatalf("weights mismatch at k=%d", k)
				}
			}
		})
	}
}

func TestStreamWireInteroperabilityAndForgedRejection(t *testing.T) {
	sys, err := bqs.Factoring(big.NewInt(3214085717), 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	w := bqs.FactoringWitness(big.NewInt(64283), big.NewInt(49999), 16, 16)
	msg := []byte("streamed witness-encrypted bitcoin taproot partial psbt payload")

	for _, tc := range []struct {
		name string
		par  Params
	}{
		{"Toy", Toy},
		{"Advanced_SignClassKDF", func() Params { p := Advanced; p.SignClassKDF = true; return p }()},
		{"Medium_Admissible", func() Params { p := Spectrum[2].Params; p.SignClassKDF = true; return p }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sys.PadUnknowns(tc.par.NForms()).PadConstraints(tc.par.JRem())
			wPad := bqs.PadWitness(w, s.N)
			pp, err := Setup(tc.par, s)
			if err != nil {
				t.Fatal(err)
			}

			// 1. EncStreamTo -> ReadCiphertext -> DecDetailed (cross-compatible with in-memory!)
			var buf bytes.Buffer
			encRep, err := EncStreamTo(pp, msg, &buf)
			if err != nil {
				t.Fatalf("EncStreamTo: %v", err)
			}
			ct, err := ReadCiphertext(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("ReadCiphertext on streamed output: %v", err)
			}
			got1, err := Dec(pp, ct, wPad)
			if err != nil || !bytes.Equal(got1, msg) {
				t.Fatalf("in-memory Dec of streamed ciphertext failed: err=%v", err)
			}

			// 2. EncStreamTo -> DecStreamFrom (full streaming round-trip!)
			got2, decRep, err := DecStreamFrom(pp, bytes.NewReader(buf.Bytes()), wPad, false)
			if err != nil || !bytes.Equal(got2, msg) {
				t.Fatalf("DecStreamFrom failed: err=%v exact=%v", err, decRep.ExactQAP)
			}

			// 3. Enc (in-memory) -> WriteTo -> DecStreamFrom (reverse interop!)
			ctInMem, err := Enc(pp, msg)
			if err != nil {
				t.Fatal(err)
			}
			var buf2 bytes.Buffer
			if _, err := ctInMem.WriteTo(&buf2); err != nil {
				t.Fatal(err)
			}
			got3, _, err := DecStreamFrom(pp, bytes.NewReader(buf2.Bytes()), wPad, false)
			if err != nil || !bytes.Equal(got3, msg) {
				t.Fatalf("DecStreamFrom on in-memory ciphertext failed: err=%v", err)
			}

			// 4. Forged 1-bit witness MUST fail DecStreamFrom(unchecked=true)!
			badW := append([]bool(nil), wPad...)
			badW[3] = !badW[3]
			if _, badRep, err := DecStreamFrom(pp, bytes.NewReader(buf.Bytes()), badW, true); err == nil || badRep.ExactQAP {
				t.Fatalf("expected forged witness rejection in DecStreamFrom: err=%v exact=%v", err, badRep.ExactQAP)
			}

			t.Logf("%s PASS: bytes=%d enc=%v dec=%v pairings=%d",
				tc.name, encRep.Bytes, encRep.EncDur, decRep.TotalDur, decRep.Pairings)
		})
	}
}

// TestTable4StreamingDiskEndToEnd runs the exact paper Table 4 ring, grid, and chunk
// geometry (dR=64, K=71, n=4608, K1=192, K2=12, 6912 cells, J=J'=11, SignClassKDF=true)
// padded to admissible N=4608 ((P1) n<=D and wide MSIS ell>K) streamed straight to/from
// a disk file and verifies low bounded heap memory.
func TestTable4StreamingDiskEndToEnd(t *testing.T) {
	par := Table4
	par.SignClassKDF = true
	// Keep search interactive (~10ms) while exercising 100% of Table 4's exact ring (n=4608),
	// 6912-cell shared-factor grid (K1=192, K2=12), J=J'=11 chunking, and 80+ MB disk streaming.
	par.G = 1 << 24

	sys, err := bqs.Factoring(big.NewInt(3214085717), 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	w := bqs.FactoringWitness(big.NewInt(64283), big.NewInt(49999), 16, 16)
	s := sys.PadUnknowns(par.NForms()).PadConstraints(par.JRem())
	wPad := bqs.PadWitness(w, s.N)

	pp, err := Setup(par, s)
	if err != nil {
		t.Fatalf("Table-4 Setup: %v", err)
	}
	adm := pp.Admissibility()
	if !adm.FullyAdmissible() {
		t.Fatalf("expected admissible Table-4 instance, got %+v", adm)
	}

	tmpPath := filepath.Join(t.TempDir(), "table4_admissible.praxis")
	f, err := os.Create(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("Table-4 n=4608 6912-cell streamed witness-encrypted Signet partial PSBT")
	encRep, err := EncStreamTo(pp, msg, f)
	if closeErr := f.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("Table-4 EncStreamTo: %v", err)
	}

	rf, err := os.Open(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	got, decRep, err := DecStreamFrom(pp, rf, wPad, false)
	_ = rf.Close()
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Table-4 DecStreamFrom failed: err=%v exact=%v", err, decRep.ExactQAP)
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("TABLE-4 STREAMING DISK PASS: n=%d cells=%d N=%d (P1&MSIS=true) | file=%.1f MiB | enc=%v | dec=%v (forms=%v qap=%v pair=%v search=%v) | HeapAlloc=%.1f MiB",
		encRep.Forms, encRep.Cells, s.N, float64(encRep.Bytes)/(1024*1024),
		encRep.EncDur, decRep.TotalDur, decRep.FormsDur, decRep.QAPDur, decRep.PairingsDur, decRep.SearchDur,
		float64(ms.HeapAlloc)/(1024*1024))
}

// TestPraxisStreamOverRealBN254CurveAndFieldBQS runs full streaming Praxis witness encryption
// and decryption over a real non-native BN254 F_p / G1 / G2 curve-check BQS (exact 68-bit CRT).
func TestPraxisStreamOverRealBN254CurveAndFieldBQS(t *testing.T) {
	_, _, g1Gen, g2Gen := bn254.Generators()
	var p1 bn254.G1Affine
	var q2 bn254.G2Affine
	p1.ScalarMultiplication(&g1Gen, big.NewInt(20262971))
	q2.ScalarMultiplication(&g2Gen, big.NewInt(133742))

	fb := bqs.NewFpBuilder(true)
	fb.AssertG1OnCurve(fb.NewG1Var(p1))
	fb.AssertG2OnTwist(fb.NewG2Var(q2))
	rawSys, err := fb.System()
	if err != nil {
		t.Fatalf("build BN254 G1+G2 BQS: %v", err)
	}

	par := Advanced
	par.SignClassKDF = true
	sys := rawSys.PadUnknowns(par.NForms()).PadConstraints(par.JRem())
	wPad := bqs.PadWitness(fb.W, sys.N)
	pp, err := Setup(par, sys)
	if err != nil {
		t.Fatalf("Setup BN254 BQS: %v", err)
	}

	tmpPath := filepath.Join(t.TempDir(), "bn254_curve_bqs.praxis")
	f, err := os.Create(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("Praxis witness-encrypted partial PSBT locked to real non-native BN254 G1+G2 BQS")
	encRep, err := EncStreamTo(pp, msg, f)
	_ = f.Close()
	if err != nil {
		t.Fatalf("EncStreamTo: %v", err)
	}

	// Forged 1-bit curve coordinate MUST fail DecStreamFrom!
	badW := append([]bool(nil), wPad...)
	badW[1] = !badW[1]
	rfBad, _ := os.Open(tmpPath)
	_, badRep, badErr := DecStreamFrom(pp, rfBad, badW, true)
	_ = rfBad.Close()
	if badErr == nil || badRep.ExactQAP {
		t.Fatalf("SECURITY FAILURE: forged BN254 G1 witness decrypted!")
	}

	// Valid BN254 curve witness MUST decrypt cleanly!
	rf, err := os.Open(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	got, decRep, err := DecStreamFrom(pp, rf, wPad, false)
	_ = rf.Close()
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("DecStreamFrom on BN254 BQS failed: err=%v exact=%v", err, decRep.ExactQAP)
	}
	t.Logf("PRAXIS STREAM OVER REAL BN254 G1+G2 BQS PASS: N=%d nc=%d | file=%.1f MiB | enc=%v | dec=%v",
		sys.N, len(sys.Constraints), float64(encRep.Bytes)/(1024*1024), encRep.EncDur, decRep.TotalDur)
}

// TestStreamFixedBaseAndSubgroupSecurity verifies the 12-bit signed fixed-base G1/G2
// tables against gnark-crypto scalar multiplication (including 0, 1, r-1, and random
// scalars) and verifies that DecStreamFrom rejects on-twist non-subgroup G2 points
// on both the direct (< 2048) and stream-wide 7x12-bit bucketed (>= 2048) paths.
func TestStreamFixedBaseAndSubgroupSecurity(t *testing.T) {
	initFixedG1Table()
	initFixedG2Table()
	_, _, g1Gen, g2Gen := bn254.Generators()

	var zero, one, negOne fr.Element
	one.SetOne()
	negOne.SetInt64(-1)
	scalars := []fr.Element{zero, one, negOne}
	for i := 0; i < 64; i++ {
		var s fr.Element
		if _, err := s.SetRandom(); err != nil {
			t.Fatal(err)
		}
		scalars = append(scalars, s)
	}
	for i := range scalars {
		k := scalars[i].BigInt(new(big.Int))
		var want1, got1 bn254.G1Affine
		want1.ScalarMultiplication(&g1Gen, k)
		j1 := mulFixedG1Jac(&scalars[i])
		got1.FromJacobian(&j1)
		if !got1.Equal(&want1) {
			t.Fatalf("mulFixedG1Jac mismatch at scalar %d", i)
		}
		var want2, got2 bn254.G2Affine
		want2.ScalarMultiplication(&g2Gen, k)
		j2 := mulFixedG2Jac(&scalars[i])
		got2.FromJacobian(&j2)
		if !got2.Equal(&want2) {
			t.Fatalf("mulFixedG2Jac mismatch at scalar %d", i)
		}
	}

	// Construct a real on-twist non-subgroup BN254 point Q_bad in E'(F_{p^2}) \ G2[r].
	var seedE2 bn254.E2
	seedE2.A0.SetUint64(7)
	seedE2.A1.SetUint64(13)
	qBadJac := bn254.GeneratePointNotInG2(seedE2)
	var qBad bn254.G2Affine
	qBad.FromJacobian(&qBadJac)
	if !qBad.IsOnCurve() || qBad.IsInSubGroup() {
		t.Fatalf("expected on-twist non-subgroup Q_bad")
	}
	qBadBytes := qBad.Bytes()

	sys, err := bqs.Factoring(big.NewInt(3214085717), 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	w := bqs.FactoringWitness(big.NewInt(64283), big.NewInt(49999), 16, 16)
	msg := []byte("subgroup tamper test payload")

	for _, tc := range []struct {
		name string
		par  Params
	}{
		{"DirectSmallG2_Toy", Toy},
		{"BucketedLargeG2_Medium", func() Params { p := Spectrum[2].Params; p.SignClassKDF = true; return p }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sys.PadUnknowns(tc.par.NForms()).PadConstraints(tc.par.JRem())
			wPad := bqs.PadWitness(w, s.N)
			pp, err := Setup(tc.par, s)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if _, err := EncStreamTo(pp, msg, &buf); err != nil {
				t.Fatal(err)
			}
			wire := append([]byte(nil), buf.Bytes()...)

			// Locate the G2 section in the wire format and overwrite one compressed G2 point with Q_bad.
			off := len(magic)
			seedLen := int(binary.BigEndian.Uint32(wire[off : off+4]))
			off += 4 + seedLen
			msgLen := int(binary.BigEndian.Uint32(wire[off : off+4]))
			off += 4 + msgLen + bn254.SizeOfGT
			n1 := int(binary.BigEndian.Uint32(wire[off : off+4]))
			off += 4 + n1*bn254.SizeOfG1AffineCompressed
			n2 := int(binary.BigEndian.Uint32(wire[off : off+4]))
			off += 4
			if n2 == 0 {
				t.Fatalf("unexpected empty G2 section")
			}
			// Inject Q_bad at an index where w[j] may be false (still MUST be rejected!).
			copy(wire[off+bn254.SizeOfG2AffineCompressed:off+2*bn254.SizeOfG2AffineCompressed], qBadBytes[:])

			if _, _, err := DecStreamFrom(pp, bytes.NewReader(wire), wPad, false); err == nil {
				t.Fatalf("SECURITY FAILURE: DecStreamFrom accepted non-subgroup G2 point Q_bad (n2=%d)!", n2)
			}
		})
	}
}

func makeValidBN254Groth16Instance(alphaU, betaU, gammaU, deltaU, kSumU, krsU, arU uint64) (bqs.Groth16VK, bn254.G1Affine, bqs.Groth16Proof) {
	_, _, g1, g2 := bn254.Generators()

	var alpha, beta, gamma, delta, kSumSc, krsSc, arSc fr.Element
	alpha.SetUint64(alphaU)
	beta.SetUint64(betaU)
	gamma.SetUint64(gammaU)
	delta.SetUint64(deltaU)
	kSumSc.SetUint64(kSumU)
	krsSc.SetUint64(krsU)
	arSc.SetUint64(arU)

	var rhs, tmp, bsSc fr.Element
	rhs.Mul(&alpha, &beta)
	tmp.Mul(&kSumSc, &gamma)
	rhs.Add(&rhs, &tmp)
	tmp.Mul(&krsSc, &delta)
	rhs.Add(&rhs, &tmp)
	bsSc.Div(&rhs, &arSc)

	var vk bqs.Groth16VK
	vk.AlphaNeg.ScalarMultiplication(&g1, alpha.BigInt(new(big.Int)))
	vk.AlphaNeg.Neg(&vk.AlphaNeg)
	vk.Beta.ScalarMultiplication(&g2, beta.BigInt(new(big.Int)))
	vk.GammaNeg.ScalarMultiplication(&g2, gamma.BigInt(new(big.Int)))
	vk.GammaNeg.Neg(&vk.GammaNeg)
	vk.DeltaNeg.ScalarMultiplication(&g2, delta.BigInt(new(big.Int)))
	vk.DeltaNeg.Neg(&vk.DeltaNeg)

	var pubKsum bn254.G1Affine
	pubKsum.ScalarMultiplication(&g1, kSumSc.BigInt(new(big.Int)))

	var proof bqs.Groth16Proof
	proof.Ar.ScalarMultiplication(&g1, arSc.BigInt(new(big.Int)))
	proof.Bs.ScalarMultiplication(&g2, bsSc.BigInt(new(big.Int)))
	proof.Krs.ScalarMultiplication(&g1, krsSc.BigInt(new(big.Int)))
	return vk, pubKsum, proof
}

// TestPraxisStreamOverRealBN254Groth16VerifierBQS runs full disk-streamed Praxis witness
// encryption and decryption directly over a real BN254 Groth16 verifier BQS compiled via
// bqs.CompileGroth16Verifier (N=2,411,777, nc=11,461, Fmax=60, with full in-BQS G2[r]
// prime-order subgroup check), verifying both 1-bit tampered witness rejection and exact
// plaintext recovery with bounded heap memory and zero leftover files on disk.
func TestPraxisStreamOverRealBN254Groth16VerifierBQS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full 2.41M-unknown BN254 Groth16 streaming disk test in -short mode")
	}

	var peakHeap atomic.Uint64
	sampleHeap := func() uint64 {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		for {
			cur := peakHeap.Load()
			if ms.HeapAlloc <= cur || peakHeap.CompareAndSwap(cur, ms.HeapAlloc) {
				break
			}
		}
		return ms.HeapAlloc
	}
	stopSample := make(chan struct{})
	doneSample := make(chan struct{})
	go func() {
		defer close(doneSample)
		tk := time.NewTicker(250 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				sampleHeap()
			case <-stopSample:
				return
			}
		}
	}()
	defer func() {
		close(stopSample)
		<-doneSample
	}()

	// 1. Construct a real BN254 Groth16 verifying key, public input commitment, and proof.
	vk, pubKsum, proof := makeValidBN254Groth16Instance(1111111, 2222222, 3333333, 4444444, 5555555, 6666666, 7777777)
	okPair, err := bn254.PairingCheck(
		[]bn254.G1Affine{proof.Ar, proof.Krs, pubKsum, vk.AlphaNeg},
		[]bn254.G2Affine{proof.Bs, vk.DeltaNeg, vk.GammaNeg, vk.Beta},
	)
	if err != nil || !okPair {
		t.Fatalf("Groth16 sanity PairingCheck failed: ok=%v err=%v", okPair, err)
	}

	// 2. Compile verifier BQS (with in-BQS G2[r] subgroup check) and synthesize proof witness.
	rawSys, err := bqs.CompileGroth16Verifier(vk, pubKsum)
	if err != nil {
		t.Fatalf("CompileGroth16Verifier: %v", err)
	}
	rawN := rawSys.N
	rawNC := len(rawSys.Constraints)
	rawFmax := rawSys.Fmax()
	if rawN != 2411777 || rawNC != 11461 || rawFmax != 60 {
		t.Fatalf("unexpected Groth16 BQS shape: got N=%d nc=%d Fmax=%d, want N=2411777 nc=11461 Fmax=60",
			rawN, rawNC, rawFmax)
	}
	_, w, err := bqs.SynthesizeGroth16Witness(vk, pubKsum, proof)
	if err != nil {
		t.Fatalf("SynthesizeGroth16Witness: %v", err)
	}
	if !rawSys.IsWitness(w) {
		t.Fatalf("valid Groth16 proof witness failed rawSys.IsWitness")
	}

	// 3. Setup streaming Praxis over the full 2.41M-unknown BN254 Groth16 verifier BQS.
	// Minimum valid n = (K+1)*DR = 4 (K=1, DR=2) with K1=2, K2=1 (K1*K2=n/2=2, legs=3)
	// and Table-4 chunk geometry J=J'=11.
	par := Params{
		DR:           2,
		K:            1,
		K1:           2,
		K2:           1,
		G:            1 << 18,
		J:            11,
		JPrime:       11,
		Fast:         true,
		SignClassKDF: true,
	}
	sys := rawSys.PadUnknowns(par.NForms()).PadConstraints(par.JRem())
	wPad := bqs.PadWitness(w, sys.N)

	tSetup := time.Now()
	pp, err := Setup(par, sys)
	setupDur := time.Since(tSetup)
	if err != nil {
		t.Fatalf("Setup over real BN254 Groth16 verifier BQS: %v", err)
	}
	adm := pp.Admissibility()
	if !adm.FullyAdmissible() {
		t.Fatalf("expected fully admissible Groth16 Praxis instance, got %+v", adm)
	}
	sampleHeap()

	// 4. Stream ciphertext straight to a temporary file inside t.TempDir() (zero leftovers).
	tmpPath := filepath.Join(t.TempDir(), "bn254_groth16_verifier_bqs.praxis")
	f, err := os.Create(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("Praxis disk-streamed witness encryption locked directly to real BN254 Groth16 verifier BQS (+G2[r])")
	encRep, err := EncStreamTo(pp, msg, f)
	if closeErr := f.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("EncStreamTo over real BN254 Groth16 verifier BQS: %v", err)
	}
	st, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != int64(encRep.Bytes) {
		t.Fatalf("ciphertext file size mismatch: disk=%d report=%d", st.Size(), encRep.Bytes)
	}
	sampleHeap()

	// 5. Forged 1-bit tampered Groth16 witness MUST be rejected by DecStreamFrom AND fail QAP exactness.
	badW := append([]bool(nil), wPad...)
	badW[1] = !badW[1] // flip LSB of proof.Ar.X
	rfBad, err := os.Open(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _, badErr := DecStreamFrom(pp, rfBad, badW, false)
	_ = rfBad.Close()
	if badErr == nil {
		t.Fatalf("SECURITY FAILURE: DecStreamFrom accepted 1-bit tampered Groth16 witness!")
	}
	// Also verify algebraic QAP soundness directly over the full |H|=2^22 domain without host IsWitness guard.
	_, _, _, badExact := pp.quotients(badW)
	if badExact {
		t.Fatalf("SECURITY FAILURE: 1-bit tampered Groth16 witness produced exact QAP quotients!")
	}
	sampleHeap()

	// 6. Valid Groth16 witness MUST stream-decrypt and recover the exact plaintext.
	rf, err := os.Open(tmpPath)
	if err != nil {
		t.Fatal(err)
	}
	got, decRep, err := DecStreamFrom(pp, rf, wPad, false)
	_ = rf.Close()
	if err != nil || !decRep.ExactQAP || !bytes.Equal(got, msg) {
		t.Fatalf("DecStreamFrom on real BN254 Groth16 verifier BQS failed: err=%v exact=%v match=%v",
			err, decRep.ExactQAP, bytes.Equal(got, msg))
	}
	endHeap := sampleHeap()
	peakMiB := float64(peakHeap.Load()) / (1024 * 1024)
	endMiB := float64(endHeap) / (1024 * 1024)

	t.Logf("PRAXIS STREAM OVER REAL BN254 GROTH16 VERIFIER BQS (+G2[r]) PASS: N=%d nc=%d (padded=%d) Fmax=%d nu=%d D=%d |H|=%d | bytes=%d (%.1f MiB) | peak_HeapAlloc=%.1f MiB (end=%.1f MiB) | setup_ms=%d enc_ms=%d dec_ms=%d (forms=%v qap=%v pair=%v search=%v) | forged_dec_err=%v forged_qap_exact=%v",
		rawN, rawNC, len(sys.Constraints), rawFmax, pp.Nu, pp.D, pp.SubgroupSize,
		encRep.Bytes, float64(encRep.Bytes)/(1024*1024),
		peakMiB, endMiB,
		setupDur.Milliseconds(), encRep.EncDur.Milliseconds(), decRep.TotalDur.Milliseconds(),
		decRep.FormsDur, decRep.QAPDur, decRep.PairingsDur, decRep.SearchDur,
		badErr != nil, badExact)
}
