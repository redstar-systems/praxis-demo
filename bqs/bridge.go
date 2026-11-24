package bqs

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	// BridgeSecretBits is the bit-length of an L2 burn preimage secret (16 bytes).
	BridgeSecretBits = 128
	// BridgeBatchSlots is the number of burn-note commitments in one L2 batch.
	BridgeBatchSlots = 4
	// BridgeQuadEquations is the number of 254-bit F_q quadratic sponge equations.
	BridgeQuadEquations = 3
	// BridgeProductsPerEq is the number of products per commitment equation (Fmax = 4 -> nu = 8).
	BridgeProductsPerEq = 4
)

// BridgeContext binds a Praxis vault ciphertext to the exact Bitcoin withdrawal
// parameters so a burn proof for one vault/recipient cannot be replayed on another.
type BridgeContext struct {
	VaultOutPoint    string `json:"vault_outpoint"`    // "<deposit_txid>:<vout>"
	RecipientAddress string `json:"recipient_address"` // "tb1p..."
	AmountSats       int64  `json:"amount_sats"`       // e.g. 99_998_000
}

// BridgeNoteCommitment is the public 3-element F_q commitment (~762 bits) of a
// 128-bit L2 burn secret bound to a specific BridgeContext.
type BridgeNoteCommitment [BridgeQuadEquations]fr.Element

// deriveBridgeForm deterministically derives a dense F_q linear form over the
// 128 secret bits w[1..128] (plus a domain constant on w[0]=1) from ctx and tags.
func deriveBridgeForm(ctx BridgeContext, eqIdx, prodIdx int, side byte) Vec {
	v := make(Vec, 0, BridgeSecretBits+1)
	var constCoeff fr.Element
	constCoeff = hashBridgeField(ctx, eqIdx, prodIdx, side, 0)
	v = append(v, Term{I: 0, V: constCoeff})
	for bit := 1; bit <= BridgeSecretBits; bit++ {
		c := hashBridgeField(ctx, eqIdx, prodIdx, side, bit)
		v = append(v, Term{I: bit, V: c})
	}
	return v
}

func hashBridgeField(ctx BridgeContext, eqIdx, prodIdx int, side byte, bit int) fr.Element {
	h := sha256.New()
	h.Write([]byte("praxis-bitcoin-signet-bridge-v1|"))
	h.Write([]byte(ctx.VaultOutPoint))
	h.Write([]byte{'|'})
	h.Write([]byte(ctx.RecipientAddress))
	h.Write([]byte{'|'})
	var buf [17]byte
	binary.LittleEndian.PutUint64(buf[0:8], uint64(ctx.AmountSats))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(eqIdx))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(prodIdx))
	buf[16] = side
	h.Write(buf[:])
	var bitBuf [4]byte
	binary.LittleEndian.PutUint32(bitBuf[:], uint32(bit))
	h.Write(bitBuf[:])
	sum := h.Sum(nil)
	var el fr.Element
	el.SetBytes(sum)
	if el.IsZero() {
		el.SetOne()
	}
	return el
}

// CommitBridgeBurn computes the public 3-element F_q commitment for a 16-byte
// L2 burn secret bound to ctx.
func CommitBridgeBurn(ctx BridgeContext, secret [16]byte) BridgeNoteCommitment {
	w := make([]bool, 1+BridgeSecretBits)
	w[0] = true
	for i := 0; i < BridgeSecretBits; i++ {
		w[1+i] = (secret[i/8]>>(uint(i)%8))&1 == 1
	}
	var out BridgeNoteCommitment
	var term fr.Element
	for eq := 0; eq < BridgeQuadEquations; eq++ {
		for m := 0; m < BridgeProductsPerEq; m++ {
			a := deriveBridgeForm(ctx, eq, m, 'A').Apply(w)
			b := deriveBridgeForm(ctx, eq, m, 'B').Apply(w)
			term.Mul(&a, &b)
			out[eq].Add(&out[eq], &term)
		}
	}
	return out
}

// BridgeBurn builds the Boolean quadratic system for an operator-free L2->Bitcoin
// bridge withdrawal:
//
//	"The prover knows a 128-bit burn secret s and one-hot batch slot j in 0..3
//	 such that Q_ctx(s) == batch[j]."
//
// Unknowns w[1..128] are the bits of s; w[129..132] are the one-hot slot flags
// sel_0..sel_3. There are 4 constraints (1 one-hot sum + 3 4-product quadratic
// commitment equations), giving N = 132, nc = 4, Fmax = 4 (coset size nu = 8).
func BridgeBurn(ctx BridgeContext, batch [BridgeBatchSlots]BridgeNoteCommitment) (*System, error) {
	if ctx.VaultOutPoint == "" || ctx.RecipientAddress == "" || ctx.AmountSats <= 0 {
		return nil, fmt.Errorf("bridge context requires non-empty vault outpoint, recipient, and positive amount")
	}
	const selBase = 1 + BridgeSecretBits
	s := &System{
		N:           BridgeSecretBits + BridgeBatchSlots,
		Constraints: make([]Constraint, 0, 1+BridgeQuadEquations),
	}

	// Constraint 0: sel_0 + sel_1 + sel_2 + sel_3 = 1 (with sel_j in {0,1},
	// exactly one slot in the L2 burn batch is selected).
	selSum := make(Vec, BridgeBatchSlots)
	for j := 0; j < BridgeBatchSlots; j++ {
		selSum[j] = T(selBase+j, 1)
	}
	s.Constraints = append(s.Constraints, Constraint{
		Products: []Product{{A: One(), B: selSum}},
		C:        One(),
	})

	// Constraints 1..3: sum_{m=0..3} A_{eq,m}(s)*B_{eq,m}(s) = sum_{j=0..3} batch[j][eq] * sel_j.
	for eq := 0; eq < BridgeQuadEquations; eq++ {
		prods := make([]Product, BridgeProductsPerEq)
		for m := 0; m < BridgeProductsPerEq; m++ {
			prods[m] = Product{
				A: deriveBridgeForm(ctx, eq, m, 'A'),
				B: deriveBridgeForm(ctx, eq, m, 'B'),
			}
		}
		rhs := make(Vec, BridgeBatchSlots)
		for j := 0; j < BridgeBatchSlots; j++ {
			rhs[j] = Term{I: selBase + j, V: batch[j][eq]}
		}
		s.Constraints = append(s.Constraints, Constraint{
			Products: prods,
			C:        rhs,
		})
	}
	return s, nil
}

// BridgeBurnWitness builds the 133-entry Boolean witness w for (slot, secret).
func BridgeBurnWitness(slot int, secret [16]byte) ([]bool, error) {
	if slot < 0 || slot >= BridgeBatchSlots {
		return nil, fmt.Errorf("slot %d outside 0..%d", slot, BridgeBatchSlots-1)
	}
	w := make([]bool, 1+BridgeSecretBits+BridgeBatchSlots)
	w[0] = true
	for i := 0; i < BridgeSecretBits; i++ {
		w[1+i] = (secret[i/8]>>(uint(i)%8))&1 == 1
	}
	w[1+BridgeSecretBits+slot] = true
	return w, nil
}
