package bqs

import (
	"testing"
)

func TestBridgeBurnSoundnessAndBinding(t *testing.T) {
	ctx := BridgeContext{
		VaultOutPoint:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:0",
		RecipientAddress: "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
		AmountSats:       99_998_000,
	}
	sec0 := [16]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01}
	sec1 := [16]byte{0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	sec2 := [16]byte{0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55}
	sec3 := [16]byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}

	batch := [BridgeBatchSlots]BridgeNoteCommitment{
		CommitBridgeBurn(ctx, sec0),
		CommitBridgeBurn(ctx, sec1),
		CommitBridgeBurn(ctx, sec2),
		CommitBridgeBurn(ctx, sec3),
	}

	sys, err := BridgeBurn(ctx, batch)
	if err != nil {
		t.Fatalf("BridgeBurn: %v", err)
	}
	if err := sys.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if sys.N != 132 || len(sys.Constraints) != 4 || sys.Fmax() != 4 {
		t.Fatalf("unexpected geometry: N=%d nc=%d Fmax=%d", sys.N, len(sys.Constraints), sys.Fmax())
	}

	// Both valid notes in the batch satisfy the system.
	w1, err := BridgeBurnWitness(1, sec1)
	if err != nil || !sys.IsWitness(w1) {
		t.Fatalf("slot 1 valid witness rejected (err=%v)", err)
	}
	w3, err := BridgeBurnWitness(3, sec3)
	if err != nil || !sys.IsWitness(w3) {
		t.Fatalf("slot 3 valid witness rejected (err=%v)", err)
	}

	// Wrong slot for a valid secret fails.
	wWrongSlot, _ := BridgeBurnWitness(2, sec1)
	if sys.IsWitness(wWrongSlot) {
		t.Fatalf("mismatched slot accepted")
	}

	// Flipping any bit of the 128-bit secret fails.
	for bit := 1; bit <= BridgeSecretBits; bit++ {
		bad := append([]bool(nil), w1...)
		bad[bit] = !bad[bit]
		if sys.IsWitness(bad) {
			t.Fatalf("flipped bit %d still satisfied system", bit)
		}
	}

	// Multi-hot or zero-hot slot selection fails.
	zeroHot := append([]bool(nil), w1...)
	zeroHot[1+BridgeSecretBits+1] = false
	if sys.IsWitness(zeroHot) {
		t.Fatalf("zero-hot slot selection accepted")
	}
	twoHot := append([]bool(nil), w1...)
	twoHot[1+BridgeSecretBits+3] = true
	if sys.IsWitness(twoHot) {
		t.Fatalf("two-hot slot selection accepted")
	}

	// Context binding: the exact same witness fails if recipient or amount changes.
	otherCtx := ctx
	otherCtx.RecipientAddress = "tb1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxq9r2hk8"
	otherSys, err := BridgeBurn(otherCtx, batch)
	if err != nil {
		t.Fatalf("otherSys: %v", err)
	}
	if otherSys.IsWitness(w1) {
		t.Fatalf("witness replayed across different recipient address")
	}
}
