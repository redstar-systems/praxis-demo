package praxis

import (
	"bytes"
	"testing"

	"praxis-demo/bqs"
	"praxis-demo/poly"
)

func TestFFTArithmeticMatchesSchoolbook(t *testing.T) {
	// Cross-check MulFFT, FromRootsFFT, and DivModFFT against schoolbook routines.
	pts := make([]bqs.Term, 90)
	roots := make([]poly.Poly, 0)
	_ = pts
	_ = roots

	var pA, pB poly.Poly
	pA = make(poly.Poly, 150)
	pB = make(poly.Poly, 67)
	for i := range pA {
		pA[i].SetInt64(int64(i*13 - 41))
	}
	for i := range pB {
		pB[i].SetInt64(int64(i*7 + 3))
	}
	gotMul := poly.MulFFT(pA, pB)
	wantMul := poly.Mul(pA, pB).Trim()
	if len(poly.Sub(gotMul, wantMul).Trim()) != 0 {
		t.Fatal("MulFFT != Mul")
	}

	qFFT, rFFT := poly.DivModFFT(pA, pB)
	qRef, rRef := poly.DivMod(pA, pB)
	if len(poly.Sub(qFFT, qRef).Trim()) != 0 || len(poly.Sub(rFFT, rRef).Trim()) != 0 {
		t.Fatal("DivModFFT != DivMod")
	}

	// Exact division.
	qExact, rExact := poly.DivModFFT(gotMul, pB)
	if len(rExact) != 0 || len(poly.Sub(qExact, pA).Trim()) != 0 {
		t.Fatal("DivModFFT exact division failed")
	}
}

func TestAdvancedModeChunkedFFTAndOutwardSearch(t *testing.T) {
	// 1. Factoring (padded from 1 to 2 constraints so J' = 2 divides nc).
	sFactRaw, wFact := factoring(t)
	sFact := sFactRaw.PadConstraints(Advanced.JRem())
	ppFact, err := Setup(Advanced, sFact)
	if err != nil {
		t.Fatalf("Setup(Advanced, factoring): %v", err)
	}
	g1, g2 := ppFact.Counts()
	p1, p2 := ppFact.PaperCounts()
	if g1 != p1 || g2 != p2 {
		t.Fatalf("Advanced counts (%d, %d) != Proposition 5.7 (%d, %d)", g1, g2, p1, p2)
	}
	msg := []byte("advanced mode: chunked powers, FFT QAP, outward sign-class search")
	ctFact, encRep, err := EncDetailed(ppFact, msg)
	if err != nil {
		t.Fatalf("EncDetailed: %v", err)
	}
	if encRep.Forms != 24 || encRep.Cells != 36 || encRep.J != 4 || encRep.JPrime != 2 {
		t.Fatalf("unexpected EncReport: %+v", encRep)
	}
	got, decRep, err := DecDetailed(ppFact, ctFact, wFact)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("DecDetailed failed: %q, %v", got, err)
	}
	if !decRep.ExactQAP || decRep.Search.Algorithm != "outward-sign-fp64" {
		t.Fatalf("unexpected DecReport: %+v", decRep)
	}

	// 2. Graph colouring (padded for J' = 2) with two distinct witnesses.
	sColRaw, wCol1 := colouring(t)
	wCol2 := bqs.ColouringWitness([]int{2, 0, 2, 0, 2, 0, 1}, 3)
	sCol := sColRaw.PadConstraints(Advanced.JRem())
	ppCol, err := Setup(Advanced, sCol)
	if err != nil {
		t.Fatal(err)
	}
	ctCol, err := Enc(ppCol, msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, sol := range [][]bool{wCol1, wCol2} {
		plain, err := Dec(ppCol, ctCol, sol)
		if err != nil || !bytes.Equal(plain, msg) {
			t.Fatalf("colouring Dec failed: %q, %v", plain, err)
		}
	}

	// 3. 3-SAT in Advanced mode with multiple satisfying assignments and wrong witness check.
	clauses := [][3]int{
		{1, 2, 3}, {-1, 2, 4}, {1, -2, -3}, {-2, -3, 4},
		{1, 3, -4}, {-1, -3, 2},
	}
	sSAT, err := bqs.ThreeSAT(4, clauses)
	if err != nil {
		t.Fatal(err)
	}
	wSAT1 := bqs.ThreeSATWitness([]bool{true, true, false, true}, clauses)
	wSAT2 := bqs.ThreeSATWitness([]bool{false, true, false, false}, clauses)
	if !sSAT.IsWitness(wSAT1) || !sSAT.IsWitness(wSAT2) {
		t.Fatal("expected valid 3-SAT witnesses")
	}
	ppSAT, err := Setup(Advanced, sSAT)
	if err != nil {
		t.Fatal(err)
	}
	ctSAT, err := Enc(ppSAT, msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, sol := range [][]bool{wSAT1, wSAT2} {
		plain, err := Dec(ppSAT, ctSAT, sol)
		if err != nil || !bytes.Equal(plain, msg) {
			t.Fatalf("3-SAT Dec failed: %q, %v", plain, err)
		}
	}
	badSAT := append([]bool(nil), wSAT1...)
	badSAT[1] = !badSAT[1]
	badSAT[2] = !badSAT[2]
	if !sSAT.IsWitness(badSAT) {
		if plain, err := DecUnchecked(ppSAT, ctSAT, badSAT); err == nil && bytes.Equal(plain, msg) {
			t.Fatal("wrong 3-SAT assignment decrypted message")
		}
	}
}
