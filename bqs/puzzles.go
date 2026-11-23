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
	if pBits < 1 || qBits < 1 || pBits+qBits > 250 {
		return nil, fmt.Errorf("factor lengths must be positive and total at most 250 bits")
	}
	if n.Sign() <= 0 || n.BitLen() > pBits+qBits {
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
	w := make([]bool, 1+len(colourOf)*colours)
	w[0] = true
	for v, c := range colourOf {
		w[1+v*colours+c] = true
	}
	return w
}
