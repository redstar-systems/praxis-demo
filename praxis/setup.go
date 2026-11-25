package praxis

import (
	"fmt"
	"math/bits"
	"runtime"
	"sync"

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

	fld          field
	cosetVanish  poly.Poly // vanishes on the cl coset points (invRev of remCoset)
	remFull      poly.Poly
	remFullAtP   []fr.Element
	remCoset     poly.Poly
	remCosetAtK  []fr.Element
}

// C0 returns the constant c0 defining F_{q^n} = F_q[T]/(T^n - c0).
func (pp *Public) C0() fr.Element { return pp.fld.c0 }

// Omega returns the order-n Frobenius scalar c0^((q-1)/n).
func (pp *Public) Omega() fr.Element { return pp.fld.omega }

func (pp *Public) nc() int          { return len(pp.S.Constraints) }
func (pp *Public) cosetLen() int    { return pp.Nu * pp.nc() }
func (pp *Public) dIndex(j int) int { return pp.cosetLen() + j }
func (pp *Public) rhoIndex() int    { return pp.D - 1 }

func reversePoly(p poly.Poly, deg int) poly.Poly {
	out := make(poly.Poly, deg+1)
	for i := 0; i <= deg; i++ {
		if deg-i < len(p) {
			out[i] = p[deg-i]
		}
	}
	return out
}

func expandStridePoly(pY poly.Poly, stride int) poly.Poly {
	if len(pY) == 0 {
		return nil
	}
	out := make(poly.Poly, (len(pY)-1)*stride+1)
	for k, c := range pY {
		out[k*stride] = c
	}
	return out
}

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
		logNu := bits.TrailingZeros(uint(nu))
		logSub := logSize - logNu
		subSize := size >> logNu

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
		pp.Points = make([]fr.Element, pp.D)
		copy(pp.Points, hBitRev[:pp.D])
		cl := pp.cosetLen()

		// Coset vanishing polynomial factors cleanly in Y = X^nu because each block
		// hBitRev[t*nu : (t+1)*nu] is an exact coset of G_nu with vanishing binomial X^nu - c_t.
		cosetRootsY := make([]fr.Element, nc)
		for t := 0; t < nc; t++ {
			cosetRootsY[t] = powers[poly.BitReverse(t, logSub)*nu]
		}
		pCosetY := poly.FromRootsFFT(cosetRootsY)
		pp.cosetVanish = expandStridePoly(pCosetY, nu)

		// Compute CosetWeights from cosetVanish'(p) = nu * p^(nu-1) * pCosetY'(p^nu)
		// using a size/nu FFT instead of a full size FFT.
		pCosetDerivSub := poly.EvalSubgroupBitRev(pCosetY.Derivative(), subSize)
		var nuFr fr.Element
		nuFr.SetUint64(uint64(nu))
		cosetDeriv := make([]fr.Element, cl)
		mask := size - 1
		for t := 0; t < nc; t++ {
			var scale fr.Element
			scale.Mul(&nuFr, &pCosetDerivSub[t])
			base := t * nu
			for j := 0; j < nu; j++ {
				e := poly.BitReverse(base+j, logSize)
				pPow := powers[(e*(nu-1))&mask]
				cosetDeriv[base+j].Mul(&scale, &pPow)
			}
		}
		pp.CosetWeights = fr.BatchInvert(cosetDeriv)

		// Build remCoset(X) = rCosetY(X^nu) vanishing on the remaining (subSize - nc) cosets.
		if cl < size {
			remRootsY := make([]fr.Element, subSize-nc)
			for t := nc; t < subSize; t++ {
				remRootsY[t-nc] = powers[poly.BitReverse(t, logSub)*nu]
			}
			rCosetY := poly.FromRootsFFT(remRootsY)
			pp.remCoset = expandStridePoly(rCosetY, nu)
			rCosetAtSub := poly.EvalSubgroupBitRev(rCosetY, subSize)
			pp.remCosetAtK = make([]fr.Element, cl)
			for t := 0; t < nc; t++ {
				val := rCosetAtSub[t]
				base := t * nu
				for j := 0; j < nu; j++ {
					pp.remCosetAtK[base+j] = val
				}
			}
		}

		// Use the exact algebraic identity X^size - 1 = ZP(X) * remFull(X) = cosetVanish(X) * Z0(X) * remFull(X)
		// to build ZP, Z, and Z0 from a single subproduct tree on the smaller tail hBitRev[D:] (or dPoints).
		if pp.D == size {
			pp.ZP = make(poly.Poly, size+1)
			pp.ZP[0].SetInt64(-1)
			pp.ZP[size].SetOne()
			pp.Z0 = pp.remCoset
			pp.Z = poly.DivLinear(pp.ZP, pp.Points[pp.D-1])
		} else {
			tailLen := size - pp.D
			z0Len := pp.D - cl
			pp.remFull = poly.FromRootsFFT(hBitRev[pp.D:])
			remFullAtH := poly.EvalSubgroupBitRev(pp.remFull, size)
			pp.remFullAtP = make([]fr.Element, pp.D)
			copy(pp.remFullAtP, remFullAtH[:pp.D])

			if z0Len <= tailLen {
				// Smaller to build Z0 directly when D is small relative to |H|.
				pp.Z0 = poly.FromRootsFFT(pp.Points[cl:])
				pp.ZP = poly.MulFFT(pp.cosetVanish, pp.Z0)
			} else {
				// Smaller to invert rev(remFull) mod X^(D+1): rev(ZP) = rev(remFull)^-1 mod X^(D+1),
				// and rev(Z0) = rev(remCoset) * rev(remFull)^-1 mod X^(z0Len+1).
				revRemFull := reversePoly(pp.remFull, tailLen)
				invRevRem := poly.InvertSeries(revRemFull, pp.D+1)
				pp.ZP = reversePoly(invRevRem, pp.D).Trim()

				revRemCoset := reversePoly(pp.remCoset, size-cl)
				if len(revRemCoset) > z0Len+1 {
					revRemCoset = revRemCoset[:z0Len+1]
				}
				invPref := invRevRem
				if len(invPref) > z0Len+1 {
					invPref = invPref[:z0Len+1]
				}
				revZ0 := poly.MulFFT(revRemCoset, invPref)
				if len(revZ0) > z0Len+1 {
					revZ0 = revZ0[:z0Len+1]
				}
				pp.Z0 = reversePoly(revZ0, z0Len).Trim()
			}
			pp.Z = poly.DivLinear(pp.ZP, pp.Points[pp.D-1])
		}

		// Barycentric weights on Points via 1 / ZP'(p_i) evaluated across H by FFT.
		zpDerivAtH := poly.EvalSubgroupBitRev(pp.ZP.Derivative(), size)
		pp.Weights = fr.BatchInvert(zpDerivAtH[:pp.D])

		z0AtH := poly.EvalSubgroupBitRev(pp.Z0, size)
		pp.Z0AtCoset = make([]fr.Element, cl)
		copy(pp.Z0AtCoset, z0AtH[:cl])
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
// identity g = f / Z', where Z' vanishes on H \ P', f interpolates vals*Z'
// across H by a single inverse FFT, and invRevZPrime = rev(Z')^{-1} mod X^{|P'|}.
func (pp *Public) fastInterpPrefix(vals []fr.Element, remPoly poly.Poly, remAtPrefix []fr.Element, invRevRem poly.Poly) poly.Poly {
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
	q, _ := poly.DivModWithInv(f, remPoly, invRevRem)
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
	if pp.D >= 16384 && runtime.NumCPU() > 1 {
		workers := runtime.NumCPU()
		chunk := (pp.D + workers - 1) / workers
		var wg sync.WaitGroup
		for wk := 0; wk < workers; wk++ {
			lo := wk * chunk
			hi := min(pp.D, lo+chunk)
			if lo >= hi {
				break
			}
			wg.Add(1)
			go func(lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					aVal[i] = pp.A[i].Apply(w)
					bVal[i] = pp.B[i].Apply(w)
				}
			}(lo, hi)
		}
		wg.Wait()
	} else {
		for i := 0; i < pp.D; i++ {
			aVal[i] = pp.A[i].Apply(w)
			bVal[i] = pp.B[i].Apply(w)
		}
	}
	cl := pp.cosetLen()
	rVal := make([]fr.Element, cl)
	inv := fr.BatchInvert(pp.Z0AtCoset)
	for i := 0; i < cl; i++ {
		rVal[i].Mul(&aVal[i], &bVal[i])
		rVal[i].Mul(&rVal[i], &inv[i])
	}

	if pp.Par.Fast {
		// Precomputed series inverses from X^size - 1 = ZP * remFull = cosetVanish * remCoset:
		//   rev(remFull)^{-1}  = rev(ZP)                        (mod X^size)
		//   rev(remCoset)^{-1} = rev(cosetVanish)               (mod X^size)
		//   rev(ZP)^{-1}       = rev(remFull)                   (mod X^size)
		//   rev(Z)^{-1}        = (1 - rho*X) * rev(remFull)     (mod X^size)
		var invRevRemFull, invRevZP poly.Poly
		if pp.D < pp.SubgroupSize {
			invRevRemFull = reversePoly(pp.ZP, pp.D)
			invRevZP = reversePoly(pp.remFull, pp.SubgroupSize-pp.D)
		} else {
			var one fr.Element
			one.SetOne()
			invRevZP = poly.Poly{one}
		}
		var invRevRemCoset poly.Poly
		if cl < pp.SubgroupSize {
			invRevRemCoset = reversePoly(pp.cosetVanish, cl)
		}
		var negRho, one fr.Element
		one.SetOne()
		negRho.Neg(&pp.Points[pp.rhoIndex()])
		// (1 - rho*X) * invRevZP in O(len(invRevZP)) time.
		invRevZ := make(poly.Poly, len(invRevZP)+1)
		invRevZ[0] = invRevZP[0]
		var tmp fr.Element
		for i := 1; i < len(invRevZP); i++ {
			tmp.Mul(&invRevZP[i-1], &negRho)
			invRevZ[i].Add(&invRevZP[i], &tmp)
		}
		invRevZ[len(invRevZP)].Mul(&invRevZP[len(invRevZP)-1], &negRho)

		aw := pp.fastInterpPrefix(aVal, pp.remFull, pp.remFullAtP, invRevRemFull)
		bw := pp.fastInterpPrefix(bVal, pp.remFull, pp.remFullAtP, invRevRemFull)
		prod := poly.MulFFT(aw, bw)
		rem = pp.fastInterpPrefix(rVal, pp.remCoset, pp.remCosetAtK, invRevRemCoset)
		rest := poly.Sub(prod, poly.MulFFT(pp.Z0, rem))
		var r1, r2 poly.Poly
		hOth, r1 = poly.DivModWithInv(rest, pp.Z, invRevZ)
		hKey, r2 = poly.DivModWithInv(poly.Sub(rest, pp.Lrho), pp.ZP, invRevZP)
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
