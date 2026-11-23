package praxis

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"praxis-demo/bqs"
)

func factoring(t *testing.T) (*bqs.System, []bool) {
	t.Helper()
	p, q := big.NewInt(64283), big.NewInt(49999) // both prime, 16 bits
	s, err := bqs.Factoring(new(big.Int).Mul(p, q), 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	return s, bqs.FactoringWitness(p, q, 16, 16)
}

// A wheel: a hub joined to a ring of six, which needs three colours.
func colouring(t *testing.T) (*bqs.System, []bool) {
	t.Helper()
	edges := [][2]int{{0, 1}, {1, 2}, {2, 3}, {3, 4}, {4, 5}, {5, 0},
		{6, 0}, {6, 1}, {6, 2}, {6, 3}, {6, 4}, {6, 5}}
	s, err := bqs.Colouring(7, 3, edges)
	if err != nil {
		t.Fatal(err)
	}
	return s, bqs.ColouringWitness([]int{0, 1, 0, 1, 0, 1, 2}, 3)
}

func TestQuotientsExactOnlyForWitness(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) (*bqs.System, []bool){
		"factoring": factoring, "colouring": colouring,
	} {
		s, w := mk(t)
		if !s.IsWitness(w) {
			t.Fatalf("%s: test solution is not a solution", name)
		}
		pp, err := Setup(Toy, s)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, exact := pp.quotients(w); !exact {
			t.Errorf("%s: divisions not exact for a solution", name)
		}
		// Flipping any one unknown breaks it (Lemma 4.7).
		for i := 1; i <= s.N; i++ {
			bad := append([]bool(nil), w...)
			bad[i] = !bad[i]
			if s.IsWitness(bad) {
				continue
			}
			if _, _, _, exact := pp.quotients(bad); exact {
				t.Errorf("%s: divisions exact for a non-solution (unknown %d flipped)", name, i)
			}
		}
	}
}

func roundTrip(t *testing.T, par Params, s *bqs.System, w []bool) {
	t.Helper()
	pp, err := Setup(par, s)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("whoever solves this may read it")
	ct, err := Enc(pp, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct.Msg, msg[:8]) {
		t.Fatal("message is in the clear")
	}

	// 1. A solution decrypts.
	got, err := Dec(pp, ct, w)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("decrypted %q, want %q", got, msg)
	}

	// 2. A wrong assignment does not, checked or unchecked.
	bad := append([]bool(nil), w...)
	bad[1] = !bad[1]
	if _, err := Dec(pp, ct, bad); !errors.Is(err, ErrNotWitness) {
		t.Fatalf("Dec with a wrong assignment: %v", err)
	}
	if got, err := DecUnchecked(pp, ct, bad); err == nil && bytes.Equal(got, msg) {
		t.Fatal("a wrong assignment decrypted the message")
	}

	// 3. The element counts are the paper's (Proposition 5.7).
	g1, g2 := pp.Counts()
	p1, p2 := pp.PaperCounts()
	if g1 != p1 || g2 != p2 || len(ct.G1) != p1 || len(ct.G2)+len(ct.G2a) != p2 {
		t.Fatalf("element counts (%d, %d), paper's formula (%d, %d)", g1, g2, p1, p2)
	}
}

func TestFactoring(t *testing.T) {
	s, w := factoring(t)
	roundTrip(t, Toy, s, w)
}

func TestColouring(t *testing.T) {
	s, w := colouring(t)
	roundTrip(t, Toy, s, w)
}

// Other grids: the paper's Figure 5 (four forms, K1 = 2, K2 = 1), and sixteen
// forms split three ways.
func TestOtherParameters(t *testing.T) {
	s, w := colouring(t)
	for _, par := range []Params{
		{DR: 2, K: 1, K1: 2, K2: 1, G: 1 << 12},
		{DR: 2, K: 1, K1: 1, K2: 2, G: 1 << 12},
		{DR: 4, K: 3, K1: 4, K2: 2, G: 1 << 16},
		{DR: 2, K: 7, K1: 2, K2: 4, G: 1 << 16},
		{DR: 8, K: 1, K1: 8, K2: 1, G: 1},
	} {
		roundTrip(t, par, s, w)
	}
}

// Two different solutions of one system both decrypt one ciphertext.
func TestAnySolutionDecrypts(t *testing.T) {
	s, w := colouring(t)
	other := bqs.ColouringWitness([]int{2, 0, 2, 0, 2, 0, 1}, 3)
	pp, err := Setup(Toy, s)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("one ciphertext, many keys")
	ct, err := Enc(pp, msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, sol := range [][]bool{w, other} {
		got, err := Dec(pp, ct, sol)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("got %q, %v", got, err)
		}
	}
}

func TestCenter(t *testing.T) {
	// ceil(4*6/2) + (8/2)*(1+3-2) = 12 + 8
	if c := center(4, 5, []bool{true, true, false, true, true}); c != 20 {
		t.Fatalf("center = %d, want 20", c)
	}
	// ceil(3*3/2) + floor((5/2)*(1+0-3/2)) = 5 + floor(-1.25) = 3
	if c := center(3, 2, []bool{true, false, false, false}); c != 3 {
		t.Fatalf("center = %d, want 3", c)
	}
}

func TestSearch(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()
	base, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		t.Fatal(err)
	}
	const bound = 5000
	for _, want := range []int64{0, 1, -1, 77, -4999, 5000, -5000} {
		var target bn254.GT
		target.Exp(base, new(big.Int).Mod(big.NewInt(want), fr.Modulus()))
		got, ok := search(&base, &target, bound)
		if !ok || got != want {
			t.Fatalf("search found %d (%v), want %d", got, ok, want)
		}
	}
	var out bn254.GT
	out.Exp(base, big.NewInt(bound+1))
	if _, ok := search(&base, &out, bound); ok {
		t.Fatal("search found a value outside its range")
	}
}

func TestFileRoundTrip(t *testing.T) {
	s, w := factoring(t)
	pp, err := Setup(Toy, s)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("through a file")
	ct, err := Enc(pp, msg)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := ct.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != ct.Size()+len("praxis-demo ciphertext 1\n")+16 {
		t.Fatalf("file is %d bytes, Size says %d", buf.Len(), ct.Size())
	}
	back, err := ReadCiphertext(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Dec(pp, back, w)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("got %q, %v", got, err)
	}
}
