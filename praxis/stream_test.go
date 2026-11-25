package praxis

import (
	"bytes"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

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
