// Package curve checks that the pairing library does what Praxis needs of it
// before any of the scheme is built on top: scalar multiplication in both
// source groups of BN254 and a bilinear pairing into the target group.
package curve

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func randScalar(t *testing.T) *big.Int {
	t.Helper()
	var s fr.Element
	if _, err := s.SetRandom(); err != nil {
		t.Fatal(err)
	}
	return s.BigInt(new(big.Int))
}

// e([a]P, [b]Q) = e(P, Q)^(ab): the identity every step of the scheme rests on.
func TestBilinear(t *testing.T) {
	_, _, g1, g2 := bn254.Generators()
	a, b := randScalar(t), randScalar(t)

	var aP bn254.G1Affine
	var bQ bn254.G2Affine
	aP.ScalarMultiplication(&g1, a)
	bQ.ScalarMultiplication(&g2, b)

	left, err := bn254.Pair([]bn254.G1Affine{aP}, []bn254.G2Affine{bQ})
	if err != nil {
		t.Fatal(err)
	}
	base, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		t.Fatal(err)
	}
	ab := new(big.Int).Mul(a, b)
	ab.Mod(ab, fr.Modulus())
	var right bn254.GT
	right.Exp(base, ab)

	if !left.Equal(&right) {
		t.Fatal("pairing is not bilinear")
	}
}

// The group order is the 254-bit prime the paper calls q (Table 4: about 2^253.6).
func TestOrder(t *testing.T) {
	if n := fr.Modulus().BitLen(); n != 254 {
		t.Fatalf("group order has %d bits, want 254", n)
	}
}
