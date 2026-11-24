package bqs

import (
	"math"
	"math/big"
	"strings"
	"testing"
)

func TestSystemValidationAndWitness(t *testing.T) {
	// Empty system rejected.
	if err := (&System{N: 1}).Validate(); err == nil {
		t.Fatal("expected error for system with no constraints")
	}
	// Constraint with no products rejected.
	if err := (&System{N: 1, Constraints: []Constraint{{}}}).Validate(); err == nil {
		t.Fatal("expected error for constraint with no products")
	}
	// Out-of-range indices rejected in A, B, and C.
	for _, bad := range []*System{
		{N: 2, Constraints: []Constraint{{Products: []Product{{A: Vec{T(-1, 1)}, B: One()}}}}},
		{N: 2, Constraints: []Constraint{{Products: []Product{{A: One(), B: Vec{T(3, 1)}}}}}},
		{N: 2, Constraints: []Constraint{{Products: []Product{{A: One(), B: One()}}, C: Vec{T(3, 1)}}}},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("expected error for out-of-range index in %+v", bad)
		}
	}

	// Valid system with N=0, duplicate indices in Vec, and zero C.
	s0 := &System{
		N: 0,
		Constraints: []Constraint{{
			Products: []Product{{A: Vec{T(0, 2), T(0, -2)}, B: One()}},
			C:        nil,
		}},
	}
	if err := s0.Validate(); err != nil {
		t.Fatalf("valid N=0 system rejected: %v", err)
	}
	if !s0.IsWitness([]bool{true}) {
		t.Fatal("w=[true] should solve 0*1 = 0")
	}
	if s0.IsWitness(nil) || s0.IsWitness([]bool{false}) || s0.IsWitness([]bool{true, false}) {
		t.Fatal("invalid witness slice accepted by IsWitness")
	}
}

func TestPuzzleValidation(t *testing.T) {
	if _, err := Factoring(big.NewInt(15), 0, 4); err == nil {
		t.Fatal("expected error for pBits=0")
	}
	if _, err := Factoring(big.NewInt(15), 126, 125); err == nil {
		t.Fatal("expected error for pBits+qBits > 250")
	}
	if _, err := Factoring(big.NewInt(0), 4, 4); err == nil {
		t.Fatal("expected error for n=0")
	}
	if _, err := Factoring(big.NewInt(256), 4, 4); err == nil {
		t.Fatal("expected error for n too large for pBits+qBits")
	}

	if _, err := Colouring(0, 3, nil); err == nil {
		t.Fatal("expected error for 0 vertices")
	}
	if _, err := Colouring(3, 0, nil); err == nil {
		t.Fatal("expected error for 0 colours")
	}
	for _, badEdge := range [][2]int{{-1, 0}, {0, 3}, {1, 1}} {
		if _, err := Colouring(3, 2, [][2]int{badEdge}); err == nil {
			t.Fatalf("expected error for bad edge %v", badEdge)
		}
	}
}

func TestRegressionSystemValidateNegativeAndNil(t *testing.T) {
	var nilSys *System
	if err := nilSys.Validate(); err == nil {
		t.Fatal("expected error for nil system")
	}
	if nilSys.IsWitness([]bool{true}) {
		t.Fatal("nil system accepted witness")
	}
	for _, negN := range []int{-1, -2, -100} {
		s := &System{
			N:           negN,
			Constraints: []Constraint{{Products: []Product{{}}}},
		}
		if err := s.Validate(); err == nil {
			t.Fatalf("System.Validate accepted N = %d", negN)
		}
		if s.IsWitness([]bool{}) {
			t.Fatalf("IsWitness accepted empty slice for N = %d", negN)
		}
	}
}

func TestRegressionColouringAndWitnessBounds(t *testing.T) {
	for _, tc := range [][2]int{{2, 1 << 62}, {1 << 62, 2}, {3037000500, 3037000500}, {2000, 2000}} {
		if _, err := Colouring(tc[0], tc[1], [][2]int{{0, 1}}); err == nil {
			t.Fatalf("Colouring(%d, %d) succeeded, expected size error", tc[0], tc[1])
		}
	}
	s, err := Colouring(2, 3, [][2]int{{0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, badColours := range [][]int{{-1, 0}, {3, 0}, {0, 3}, {0, -5}} {
		w := ColouringWitness(badColours, 3)
		if s.IsWitness(w) {
			t.Fatalf("out-of-range colour %v produced valid witness", badColours)
		}
	}
	if w := ColouringWitness([]int{0}, 0); w != nil {
		t.Fatalf("expected nil witness for colours=0, got %v", w)
	}
}

func TestRegressionFactoringOverflowAndNil(t *testing.T) {
	if _, err := Factoring(nil, 4, 4); err == nil {
		t.Fatal("expected error for nil n")
	}
	_, err := Factoring(big.NewInt(15), math.MaxInt, math.MaxInt)
	if err == nil || strings.Contains(err.Error(), "-2 bits") {
		t.Fatalf("Factoring overflowed pBits+qBits: got err=%v", err)
	}
}
