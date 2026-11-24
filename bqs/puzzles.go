package bqs

import (
	"fmt"
	"math/big"
)

// Factoring is the statement "n = p * q, with p of at most pBits bits and q
// of at most qBits bits". The unknowns are the bits of p then the bits of q,
// lowest first, and the whole statement is one equation with one product.
// Choosing pBits and qBits below the length of n rules out the factor 1.
func Factoring(n *big.Int, pBits, qBits int) (*System, error) {
	if pBits < 1 || qBits < 1 || pBits > 250 || qBits > 250 || pBits+qBits > 250 {
		return nil, fmt.Errorf("factor lengths must be positive and total at most 250 bits")
	}
	if n == nil || n.Sign() <= 0 || n.BitLen() > pBits+qBits {
		return nil, fmt.Errorf("n must be positive and fit in %d bits", pBits+qBits)
	}
	bits := func(first, count int) Vec {
		v := make(Vec, count)
		for i := range v {
			v[i].I = first + i
			v[i].V.SetBigInt(new(big.Int).Lsh(big.NewInt(1), uint(i)))
		}
		return v
	}
	var c Term
	c.V.SetBigInt(n)
	return &System{
		N: pBits + qBits,
		Constraints: []Constraint{{
			Products: []Product{{A: bits(1, pBits), B: bits(1+pBits, qBits)}},
			C:        Vec{c},
		}},
	}, nil
}

// FactoringWitness is the assignment for the factors p and q.
func FactoringWitness(p, q *big.Int, pBits, qBits int) []bool {
	w := make([]bool, 1+pBits+qBits)
	w[0] = true
	for i := 0; i < pBits; i++ {
		w[1+i] = p.Bit(i) == 1
	}
	for i := 0; i < qBits; i++ {
		w[1+pBits+i] = q.Bit(i) == 1
	}
	return w
}

// Colouring is the statement "this graph can be coloured with the given
// number of colours so that no edge joins two vertices of one colour".
// Unknown 1 + v*colours + c says vertex v has colour c. Each vertex gets one
// equation (exactly one colour) and each edge one equation that sums a
// product per colour, which is the many-products case the paper's cosets are
// for.
func Colouring(vertices, colours int, edges [][2]int) (*System, error) {
	if vertices < 1 || colours < 1 {
		return nil, fmt.Errorf("need at least one vertex and one colour")
	}
	const maxVars = 1 << 20
	if vertices > maxVars || colours > maxVars/vertices {
		return nil, fmt.Errorf("graph too large (%d vertices, %d colours)", vertices, colours)
	}
	x := func(v, c int) int { return 1 + v*colours + c }
	s := &System{N: vertices * colours}
	for v := 0; v < vertices; v++ {
		sum := make(Vec, colours)
		for c := range sum {
			sum[c] = T(x(v, c), 1)
		}
		s.Constraints = append(s.Constraints, Constraint{
			Products: []Product{{A: One(), B: sum}},
			C:        One(),
		})
	}
	for _, e := range edges {
		if e[0] < 0 || e[0] >= vertices || e[1] < 0 || e[1] >= vertices || e[0] == e[1] {
			return nil, fmt.Errorf("bad edge %v", e)
		}
		con := Constraint{}
		for c := 0; c < colours; c++ {
			con.Products = append(con.Products, Product{
				A: Vec{T(x(e[0], c), 1)},
				B: Vec{T(x(e[1], c), 1)},
			})
		}
		s.Constraints = append(s.Constraints, con)
	}
	return s, nil
}

// ColouringWitness is the assignment for a colour per vertex.
func ColouringWitness(colourOf []int, colours int) []bool {
	if colours < 1 || len(colourOf) > (1<<20)/colours {
		return nil
	}
	w := make([]bool, 1+len(colourOf)*colours)
	w[0] = true
	for v, c := range colourOf {
		if c >= 0 && c < colours {
			w[1+v*colours+c] = true
		}
	}
	return w
}

// ThreeSAT encodes a 3-CNF formula in vars Boolean variables (1..vars). Each
// clause holds three signed literals (+v for x_v, -v for 1 - x_v). Following
// Section 4.1's gate encoding, clause c introduces one auxiliary unknown
// y_c = (1 - l_1)(1 - l_2) and enforces y_c * (1 - l_3) = 0, giving 2*len(clauses)
// R1CS constraints in vars + len(clauses) unknowns.
func ThreeSAT(vars int, clauses [][3]int) (*System, error) {
	if vars < 1 || len(clauses) == 0 {
		return nil, fmt.Errorf("3-SAT needs at least one variable and one clause")
	}
	if vars > 1<<19 || len(clauses) > 1<<19 {
		return nil, fmt.Errorf("3-SAT formula too large")
	}
	negLit := func(lit int) (Vec, error) {
		if lit > 0 && lit <= vars {
			return Vec{T(0, 1), T(lit, -1)}, nil
		}
		if lit < 0 && -lit <= vars {
			return Vec{T(-lit, 1)}, nil
		}
		return nil, fmt.Errorf("literal %d outside +-1..%d", lit, vars)
	}
	s := &System{
		N:           vars + len(clauses),
		Constraints: make([]Constraint, 0, 2*len(clauses)),
	}
	for cIdx, cl := range clauses {
		nl1, err := negLit(cl[0])
		if err != nil {
			return nil, err
		}
		nl2, err := negLit(cl[1])
		if err != nil {
			return nil, err
		}
		nl3, err := negLit(cl[2])
		if err != nil {
			return nil, err
		}
		yc := vars + 1 + cIdx
		s.Constraints = append(s.Constraints,
			Constraint{
				Products: []Product{{A: nl1, B: nl2}},
				C:        Vec{T(yc, 1)},
			},
			Constraint{
				Products: []Product{{A: Vec{T(yc, 1)}, B: nl3}},
				C:        nil,
			},
		)
	}
	return s, nil
}

// ThreeSATWitness extends a variable assignment x (length vars, 0-indexed for
// x_1..x_vars) with the auxiliary clause-gate values y_c.
func ThreeSATWitness(x []bool, clauses [][3]int) []bool {
	vars := len(x)
	w := make([]bool, 1+vars+len(clauses))
	w[0] = true
	copy(w[1:1+vars], x)
	litFalse := func(lit int) bool {
		if lit > 0 && lit <= vars {
			return !x[lit-1]
		}
		if lit < 0 && -lit <= vars {
			return x[-lit-1]
		}
		return false
	}
	for cIdx, cl := range clauses {
		w[1+vars+cIdx] = litFalse(cl[0]) && litFalse(cl[1])
	}
	return w
}
