package praxis

import (
	"fmt"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"praxis-demo/bqs"
	"praxis-demo/poly"
)

// Public is the output of Setup: the system and its polynomial encoding (the
// paper's QAP, Definition 4.6). Setup is deterministic and has no secret, so
// anyone can recompute it from the system.
//
// The evaluation points are ordered: the nc cosets of nu points each, then
// d_0..d_N, then rho.
type Public struct {
	Par          Params
	S            *bqs.System
	Nu           int // coset size: the least power of two above the most products in a constraint
	D            int // number of evaluation points, N + 2 + Nu*nc
	SubgroupSize int // |H| = 2^ceil(log2 D)
	Delta        int // quotient chunk size, ceil(D / J)
	DeltaPrime   int // remainder chunk size, Nu*nc / J'

	Points  []fr.Element
	Weights []fr.Element // barycentric weights on Points
	A, B    []bqs.Vec    // the vectors A(p) and B(p) at each point

	CosetWeights []fr.Element // barycentric weights on the coset points alone
	Z0AtCoset    []fr.Element // Z0(p) at each coset point

	ZP   poly.Poly // vanishes on every point: Z(X) * (X - rho)
	Z    poly.Poly // vanishes on every point but rho
	Z0   poly.Poly // vanishes on d_0..d_N and rho
	Lrho poly.Poly // 1 at rho, 0 at every other point

	fld         field
	remFull     poly.Poly
	remFullAtP  []fr.Element
	remCoset    poly.Poly
	remCosetAtK []fr.Element
}

// C0 returns the constant c0 defining F_{q^n} = F_q[T]/(T^n - c0).
func (pp *Public) C0() fr.Element { return pp.fld.c0 }

// Omega returns the order-n Frobenius scalar c0^((q-1)/n).
func (pp *Public) Omega() fr.Element { return pp.fld.omega }

func (pp *Public) nc() int          { return len(pp.S.Constraints) }
func (pp *Public) cosetLen() int    { return pp.Nu * pp.nc() }
func (pp *Public) dIndex(j int) int { return pp.cosetLen() + j }
func (pp *Public) rhoIndex() int    { return pp.D - 1 }

// Setup builds the polynomial encoding of a system.
func Setup(par Params, s *bqs.System) (*Public, error) {
	if err := par.Validate(); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	const maxDomain = 1 << 28
	nc := len(s.Constraints)
	fmax := s.Fmax()
	if s.N > maxDomain || nc > maxDomain || fmax >= maxDomain {
		return nil, fmt.Errorf("system too large")
	}
	jQuo, jRem := par.JQuo(), par.JRem()
	if nc%jRem != 0 {
		return nil, fmt.Errorf("JPrime=%d must divide constraint count %d", jRem, nc)
	}
	nu := 2
	for nu <= fmax {
		nu *= 2
	}
	if nu > maxDomain/nc || s.N+2+nu*nc > maxDomain {
		return nil, fmt.Errorf("system too large")
	}
	d := s.N + 2 + nu*nc
	size := nu
	for size < d {
		size *= 2
	}
	if size > maxDomain {
		return nil, fmt.Errorf("system too large")
	}
	pp := &Public{
		Par:          par,
		S:            s,
		Nu:           nu,
		D:            d,
		SubgroupSize: size,
		Delta:        (d + jQuo - 1) / jQuo,
		DeltaPrime:   (nu * nc) / jRem,
		fld:          newField(par.NForms()),
	}

	if par.Fast {
		// Section 4.4: place evaluation points in H of order 2^ceil(log2 D) in
		// bit-reversed order of powers of h, which automatically groups the first
		// nu*nc entries into nc disjoint cosets of order nu, followed by d_0..d_N, rho.
		logSize := bits.TrailingZeros(uint(size))
		h := poly.RootOfUnity2Pow(logSize)
		powers := make([]fr.Element, size)
		powers[0].SetOne()
		for i := 1; i < size; i++ {
			powers[i].Mul(&powers[i-1], &h)
		}
		hBitRev := make([]fr.Element, size)
		for i := 0; i < size; i++ {
			hBitRev[i] = powers[poly.BitReverse(i, logSize)]
		}
		pp.Points = hBitRev[:pp.D]

		pp.ZP = poly.FromRootsFFT(pp.Points)
		pp.Z = poly.FromRootsFFT(pp.Points[:pp.D-1])
		pp.Z0 = poly.FromRootsFFT(pp.Points[pp.cosetLen():])

		// Barycentric weights on Points via 1 / ZP'(p_i) evaluated across H by FFT.
		zpDerivAtH := poly.EvalSubgroupBitRev(pp.ZP.Derivative(), size)
		pp.Weights = fr.BatchInvert(zpDerivAtH[:pp.D])

		cl := pp.cosetLen()
		cosetVanish := poly.FromRootsFFT(pp.Points[:cl])
		cosetDerivAtH := poly.EvalSubgroupBitRev(cosetVanish.Derivative(), size)
		pp.CosetWeights = fr.BatchInvert(cosetDerivAtH[:cl])

		z0AtH := poly.EvalSubgroupBitRev(pp.Z0, size)
		pp.Z0AtCoset = z0AtH[:cl]

		if pp.D < size {
			pp.remFull = poly.FromRootsFFT(hBitRev[pp.D:])
			pp.remFullAtP = poly.EvalSubgroupBitRev(pp.remFull, size)[:pp.D]
		}
		if cl < size {
			pp.remCoset = poly.FromRootsFFT(hBitRev[cl:])
			pp.remCosetAtK = poly.EvalSubgroupBitRev(pp.remCoset, size)[:cl]
		}
	} else {
		// Plain mode: coset t is h^t times the subgroup of order nu; the single
		// points are taken from the cosets left over.
		h := rootOfUnity(size)
		step := size / nu
		powers := make([]fr.Element, size)
		powers[0].SetOne()
		for i := 1; i < size; i++ {
			powers[i].Mul(&powers[i-1], &h)
		}
		for t := 0; t < nc; t++ {
			for j := 0; j < nu; j++ {
				pp.Points = append(pp.Points, powers[t+j*step])
			}
		}
		for e := 0; e < size && len(pp.Points) < pp.D; e++ {
			if e%step >= nc {
				pp.Points = append(pp.Points, powers[e])
			}
		}
		if len(pp.Points) != pp.D {
			return nil, fmt.Errorf("could not place %d evaluation points", pp.D)
		}

		pp.Weights = poly.Weights(pp.Points)
		pp.CosetWeights = poly.Weights(pp.Points[:pp.cosetLen()])
		pp.ZP = poly.FromRoots(pp.Points)
		pp.Z = poly.FromRoots(pp.Points[:pp.D-1])
		pp.Z0 = poly.FromRoots(pp.Points[pp.cosetLen():])

		pp.Z0AtCoset = make([]fr.Element, pp.cosetLen())
		for i := range pp.Z0AtCoset {
			pp.Z0AtCoset[i] = pp.Z0.Eval(&pp.Points[i])
		}
	}

	zAtRho := pp.Z.Eval(&pp.Points[pp.rhoIndex()])
	zAtRho.Inverse(&zAtRho)
	pp.Lrho = poly.Scale(pp.Z, &zAtRho)

	// The table of Definition 4.6.
	pp.A = make([]bqs.Vec, pp.D)
	pp.B = make([]bqs.Vec, pp.D)
	scaled := func(v bqs.Vec, c *fr.Element) bqs.Vec {
		out := make(bqs.Vec, len(v))
		for i, t := range v {
			out[i].I = t.I
			out[i].V.Mul(&t.V, c)
		}
		return out
	}
	var minusOne fr.Element
	minusOne.SetInt64(-1)
	for t, con := range s.Constraints {
		for f, p := range con.Products {
			i := t*nu + f
			pp.A[i] = scaled(p.A, &pp.Z0AtCoset[i])
			pp.B[i] = p.B
		}
		i := t*nu + len(con.Products)
		pp.A[i] = scaled(bqs.One(), &pp.Z0AtCoset[i])
		pp.B[i] = scaled(con.C, &minusOne)
	}
	pp.B[pp.dIndex(0)] = bqs.One()
	for j := 1; j <= s.N; j++ {
		pp.A[pp.dIndex(j)] = bqs.Vec{bqs.T(j, 1), bqs.T(0, -1)}
		pp.B[pp.dIndex(j)] = bqs.Vec{bqs.T(j, 1)}
	}
	pp.A[pp.rhoIndex()] = bqs.One()
	pp.B[pp.rhoIndex()] = bqs.One()
	return pp, nil
}

// fastInterpPrefix interpolates vals on a prefix P' of H using Proposition 5.7's
// identity g = f / Z', where Z' vanishes on H \ P' and f interpolates vals*Z'
// (extended by zeros on H \ P') across H by a single inverse FFT.
func (pp *Public) fastInterpPrefix(vals []fr.Element, remPoly poly.Poly, remAtPrefix []fr.Element) poly.Poly {
	size := pp.SubgroupSize
	fVals := make([]fr.Element, size)
	if len(vals) == size {
		copy(fVals, vals)
		return poly.InterpSubgroupBitRev(fVals).Trim()
	}
	for i := range vals {
		fVals[i].Mul(&vals[i], &remAtPrefix[i])
	}
	f := poly.InterpSubgroupBitRev(fVals)
	q, _ := poly.DivModFFT(f, remPoly)
	return q
}

// allowed reports whether no exponent of r is divisible by nu.
func (pp *Public) allowed(r poly.Poly) bool {
	for k := 0; k < len(r); k += pp.Nu {
		if !r[k].IsZero() {
			return false
		}
	}
	return true
}

// quotients computes, for an assignment w, the polynomials of the paper's
// Equation (4): with Aw = sum of w_i A_i and Bw likewise,
//
//	Aw*Bw - Lrho = hKey * Z * (X - rho) + Z0 * rem
//	Aw*Bw        = hOth * Z             + Z0 * rem
//
// exact reports whether both divisions left no remainder and rem is allowed,
// which holds exactly when w is a witness (Lemma 4.7).
func (pp *Public) quotients(w []bool) (hKey, hOth, rem poly.Poly, exact bool) {
	aVal := make([]fr.Element, pp.D)
	bVal := make([]fr.Element, pp.D)
	for i := 0; i < pp.D; i++ {
		aVal[i] = pp.A[i].Apply(w)
		bVal[i] = pp.B[i].Apply(w)
	}
	cl := pp.cosetLen()
	rVal := make([]fr.Element, cl)
	inv := fr.BatchInvert(pp.Z0AtCoset)
	for i := 0; i < cl; i++ {
		rVal[i].Mul(&aVal[i], &bVal[i])
		rVal[i].Mul(&rVal[i], &inv[i])
	}

	if pp.Par.Fast {
		aw := pp.fastInterpPrefix(aVal, pp.remFull, pp.remFullAtP)
		bw := pp.fastInterpPrefix(bVal, pp.remFull, pp.remFullAtP)
		prod := poly.MulFFT(aw, bw)
		rem = pp.fastInterpPrefix(rVal, pp.remCoset, pp.remCosetAtK)
		rest := poly.Sub(prod, poly.MulFFT(pp.Z0, rem))
		var r1, r2 poly.Poly
		hOth, r1 = poly.DivModFFT(rest, pp.Z)
		hKey, r2 = poly.DivModFFT(poly.Sub(rest, pp.Lrho), pp.ZP)
		exact = len(r1) == 0 && len(r2) == 0 && pp.allowed(rem)
		return hKey, hOth, rem, exact
	}

	aw := poly.Interpolate(pp.Points, pp.Weights, aVal)
	bw := poly.Interpolate(pp.Points, pp.Weights, bVal)
	prod := poly.Mul(aw, bw)
	rem = poly.Interpolate(pp.Points[:cl], pp.CosetWeights, rVal)
	rest := poly.Sub(prod, poly.Mul(pp.Z0, rem))
	hOth, r1 := poly.DivMod(rest, pp.Z)
	hKey, r2 := poly.DivMod(poly.Sub(rest, pp.Lrho), pp.ZP)
	exact = len(r1) == 0 && len(r2) == 0 && pp.allowed(rem)
	return hKey, hOth, rem, exact
}
