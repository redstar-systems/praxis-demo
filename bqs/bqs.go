// Package bqs holds Boolean quadratic systems (the paper's Definition 4.1):
// lists of quadratic equations whose unknowns must each be 0 or 1. They are
// the statements Praxis encrypts to, and a solution is what decrypts.
package bqs

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Term is one entry of a sparse vector: coefficient V at index I.
type Term struct {
	I int
	V fr.Element
}

// Vec is a sparse vector with indices 0..N. Index 0 is the constant term,
// because every assignment has w[0] = 1. As a linear form it maps an
// assignment w to the sum of V * w[I].
type Vec []Term

// Product is one product a(w) * b(w) on the left of a constraint.
type Product struct{ A, B Vec }

// Constraint reads: sum over its products of a(w) b(w) = c(w).
type Constraint struct {
	Products []Product
	C        Vec
}

// System is a Boolean quadratic system in N unknowns w[1..N].
type System struct {
	N           int
	Constraints []Constraint
}

// T builds a term with a small integer coefficient.
func T(i int, v int64) Term {
	var t Term
	t.I = i
	t.V.SetInt64(v)
	return t
}

// One is the constant form 1.
func One() Vec { return Vec{T(0, 1)} }

// Fmax is the largest number of products in one constraint.
func (s *System) Fmax() int {
	m := 1
	for _, c := range s.Constraints {
		m = max(m, len(c.Products))
	}
	return m
}

// PadConstraints returns a copy of s padded with 0 = 0 constraints (Section 4.1
// and Section 5.2) so that len(Constraints) is a multiple of mult.
func (s *System) PadConstraints(mult int) *System {
	if s == nil || mult <= 1 || len(s.Constraints)%mult == 0 {
		return s
	}
	rem := mult - (len(s.Constraints) % mult)
	cons := make([]Constraint, len(s.Constraints), len(s.Constraints)+rem)
	copy(cons, s.Constraints)
	for i := 0; i < rem; i++ {
		cons = append(cons, Constraint{Products: []Product{{}}})
	}
	return &System{N: s.N, Constraints: cons}
}

// Validate checks that every index is in range and every constraint has a
// product.
func (s *System) Validate() error {
	if s == nil {
		return fmt.Errorf("nil system")
	}
	if s.N < 0 {
		return fmt.Errorf("negative unknown count %d", s.N)
	}
	check := func(v Vec) error {
		for _, t := range v {
			if t.I < 0 || t.I > s.N {
				return fmt.Errorf("index %d outside 0..%d", t.I, s.N)
			}
		}
		return nil
	}
	if len(s.Constraints) == 0 {
		return fmt.Errorf("system has no constraints")
	}
	for i, c := range s.Constraints {
		if len(c.Products) == 0 {
			return fmt.Errorf("constraint %d has no product", i)
		}
		if err := check(c.C); err != nil {
			return fmt.Errorf("constraint %d: %w", i, err)
		}
		for _, p := range c.Products {
			if err := check(p.A); err != nil {
				return fmt.Errorf("constraint %d: %w", i, err)
			}
			if err := check(p.B); err != nil {
				return fmt.Errorf("constraint %d: %w", i, err)
			}
		}
	}
	return nil
}

// Apply evaluates the form v on the assignment w (len N+1, w[0] true).
func (v Vec) Apply(w []bool) fr.Element {
	var acc fr.Element
	for _, t := range v {
		if w[t.I] {
			acc.Add(&acc, &t.V)
		}
	}
	return acc
}

// IsWitness reports whether w solves the system. w has N+1 entries and w[0]
// must be true.
func (s *System) IsWitness(w []bool) bool {
	if s == nil || s.N < 0 || len(w) != s.N+1 || !w[0] {
		return false
	}
	var sum, t fr.Element
	for _, c := range s.Constraints {
		sum.SetZero()
		for _, p := range c.Products {
			a, b := p.A.Apply(w), p.B.Apply(w)
			t.Mul(&a, &b)
			sum.Add(&sum, &t)
		}
		rhs := c.C.Apply(w)
		if !sum.Equal(&rhs) {
			return false
		}
	}
	return true
}
