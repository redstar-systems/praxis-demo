package praxis

import (
	"bytes"
	"math/big"
	"testing"

	"praxis-demo/bqs"
)

func TestFullSpectrumTiersUpToTable4(t *testing.T) {
	p, q := big.NewInt(4294967291), big.NewInt(4294967279)
	rawSys, err := bqs.Factoring(new(big.Int).Mul(p, q), 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	wValid := bqs.FactoringWitness(p, q, 32, 32)
	msg := []byte("table-4-spectrum-verified")

	for _, tier := range Spectrum {
		if err := tier.Params.Validate(); err != nil {
			t.Fatalf("tier %d (%s) invalid: %v", tier.Index, tier.Name, err)
		}
		if testing.Short() && tier.Index > 4 {
			continue
		}
		sys := rawSys.PadConstraints(tier.Params.JRem())
		pp, err := Setup(tier.Params, sys)
		if err != nil {
			t.Fatalf("tier %d Setup: %v", tier.Index, err)
		}
		ct, encRep, err := EncDetailed(pp, msg)
		if err != nil {
			t.Fatalf("tier %d EncDetailed: %v", tier.Index, err)
		}
		got, decRep, err := DecDetailed(pp, ct, wValid)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("tier %d DecDetailed failed: got=%q err=%v", tier.Index, got, err)
		}
		t.Logf("Tier %d %-10s n=%4d cells=%4d g=2^%.1f | CT=%7.1f KB | Enc=%6v | Dec=%6v (search=%6v, baby=%d, giant=%d, workers=%d)",
			tier.Index, tier.Name, tier.Params.NForms(), tier.Params.Cells(),
			tier.AdmissibilityLogG(), float64(encRep.Bytes)/1024.0,
			encRep.EncDur, decRep.TotalDur, decRep.SearchDur,
			decRep.Search.BabySteps, decRep.Search.GiantSteps, decRep.Search.Workers)
	}
}

func (t Tier) AdmissibilityLogG() float64 {
	// helper for readable test logs
	x := float64(t.Params.G)
	out := 0.0
	for x >= 2 {
		x /= 2
		out++
	}
	return out + (x - 1)
}

func TestAdmissibilityWithPadUnknowns(t *testing.T) {
	p, q := big.NewInt(17), big.NewInt(19)
	rawSys, err := bqs.Factoring(new(big.Int).Mul(p, q), 6, 6)
	if err != nil {
		t.Fatal(err)
	}
	w := bqs.FactoringWitness(p, q, 6, 6)

	// Check Tier 3 (n=96): initially inadmissible on N=12, becomes FullyAdmissible after PadUnknowns.
	par := Spectrum[2].Params
	ppSmall, err := Setup(par, rawSys.PadConstraints(par.JRem()))
	if err != nil {
		t.Fatal(err)
	}
	adm0 := ppSmall.Admissibility()
	if adm0.FullyAdmissible() {
		t.Fatalf("expected small N=%d to fail (P1)/MSIS at n=%d: %+v", rawSys.N, par.NForms(), adm0)
	}

	paddedSys := rawSys.PadUnknowns(adm0.MinAdmissibleN).PadConstraints(par.JRem())
	ppAdmissible, err := Setup(par, paddedSys)
	if err != nil {
		t.Fatal(err)
	}
	adm1 := ppAdmissible.Admissibility()
	if !adm1.FullyAdmissible() {
		t.Fatalf("expected padded N=%d to satisfy (P1) and Ell > K: %+v", paddedSys.N, adm1)
	}
	wPadded := bqs.PadWitness(w, paddedSys.N)
	ct, err := Enc(ppAdmissible, []byte("admissible-ok"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Dec(ppAdmissible, ct, wPadded)
	if err != nil || string(got) != "admissible-ok" {
		t.Fatalf("padded admissible round-trip failed: %q, %v", got, err)
	}
}
