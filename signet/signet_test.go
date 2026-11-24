package signet

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"praxis-demo/bqs"
	"praxis-demo/praxis"
)

func TestMainnetPortGuardrailAndChecksum(t *testing.T) {
	for _, port := range []string{"127.0.0.1:8332", "127.0.0.1:8382"} {
		_, err := NewRPCClient(port, "/nonexistent", "u:p")
		if err == nil || !strings.Contains(err.Error(), "safety block") {
			t.Fatalf("expected safety block on %s, got %v", port, err)
		}
	}
	if _, err := NewRPCClient("192.168.1.10:38401", "/nonexistent", "u:p"); err == nil {
		t.Fatalf("expected non-loopback host rejection")
	}
	// BIP-380 test vector: raw(deadbeef) -> checksum 89f8spxm
	got, err := DescriptorChecksum("raw(deadbeef)")
	if err != nil || got != "89f8spxm" {
		t.Fatalf("DescriptorChecksum(\"raw(deadbeef)\") = %q, %v; want 89f8spxm", got, err)
	}
}

func TestEphemeralSignet2of2TaprootPraxisBridgeEndToEnd(t *testing.T) {
	if _, err := FindBitcoind(false); err != nil {
		t.Skipf("bitcoind not installed locally: %v", err)
	}
	env, err := StartEphemeral()
	if err != nil {
		t.Fatalf("StartEphemeral: %v", err)
	}
	defer env.Close()

	// 1. Lock 1.0 sBTC in a 2-of-2 tr(NUMS, multi_a(2, Depositor, Claimer)) Taproot vault.
	//    Both Depositor and Claimer wallets keep their private keys LIVE.
	vault, err := env.LockTaprootVault()
	if err != nil {
		t.Fatalf("LockTaprootVault: %v", err)
	}
	if !strings.HasPrefix(vault.VaultAddress, "tb1p") || !strings.HasPrefix(vault.RecipientAddress, "tb1p") {
		t.Fatalf("expected signet bech32m tb1p addresses, got vault=%s recipient=%s", vault.VaultAddress, vault.RecipientAddress)
	}
	if len(vault.DepositorSigHex) != 128 {
		t.Fatalf("expected 64-byte Depositor Schnorr sig (128 hex chars), got %d (%s)", len(vault.DepositorSigHex), vault.DepositorSigHex)
	}

	// 2. Verify NEITHER party can unilaterally spend the vault even with live keys.
	depRug, err := env.AttemptUnilateralSpend(vault, "depositor")
	if err != nil {
		t.Fatalf("AttemptUnilateralSpend(depositor): %v", err)
	}
	if !depRug.WalletKeysLive || !depRug.PartialSigned || depRug.FinalizableAlone {
		t.Fatalf("expected depositor live-key rug-pull to produce 1-of-2 partial sig and fail finalization: %+v", depRug)
	}
	clmEarly, err := env.AttemptUnilateralSpend(vault, "claimer")
	if err != nil {
		t.Fatalf("AttemptUnilateralSpend(claimer): %v", err)
	}
	if !clmEarly.WalletKeysLive || !clmEarly.PartialSigned || clmEarly.FinalizableAlone {
		t.Fatalf("expected claimer premature spend to produce 1-of-2 partial sig and fail finalization: %+v", clmEarly)
	}

	// 3. Build the L2 burn-commitment batch bound to this exact Bitcoin withdrawal,
	//    encrypt Depositor's 1-of-2 partial PSBT with Praxis, and wipe the plaintext copy.
	ctx := bqs.BridgeContext{
		VaultOutPoint:    vault.OutPoint(),
		RecipientAddress: vault.RecipientAddress,
		AmountSats:       vault.WithdrawSats,
	}
	var secrets [bqs.BridgeBatchSlots][16]byte
	for i := range secrets {
		if _, err := rand.Read(secrets[i][:]); err != nil {
			t.Fatal(err)
		}
	}
	var batch [bqs.BridgeBatchSlots]bqs.BridgeNoteCommitment
	for i := range batch {
		batch[i] = bqs.CommitBridgeBurn(ctx, secrets[i])
	}
	sys, err := bqs.BridgeBurn(ctx, batch)
	if err != nil {
		t.Fatalf("BridgeBurn: %v", err)
	}

	pp, err := praxis.Setup(praxis.Advanced, sys.PadConstraints(praxis.Advanced.JRem()))
	if err != nil {
		t.Fatalf("praxis.Setup: %v", err)
	}
	expectedPSBT := append([]byte(nil), vault.DepositorPartialPSBT...)
	ct, _, err := praxis.EncDetailed(pp, vault.DepositorPartialPSBT)
	if err != nil {
		t.Fatalf("praxis.EncDetailed: %v", err)
	}
	for i := range vault.DepositorPartialPSBT {
		vault.DepositorPartialPSBT[i] = 0
	}

	// 4. Forged burn proof fails DecUnchecked and leaves the 2-of-2 Signet UTXO unspent.
	wValid1, err := bqs.BridgeBurnWitness(1, secrets[1])
	if err != nil {
		t.Fatal(err)
	}
	wForged := append([]bool(nil), wValid1...)
	wForged[7] = !wForged[7]
	if _, err := praxis.DecUnchecked(pp, ct, wForged); err == nil {
		t.Fatalf("forged burn proof unexpectedly decrypted")
	}
	unspent, err := env.IsOutPointUnspent(vault.DepositTxID, vault.DepositVout)
	if err != nil || !unspent {
		t.Fatalf("vault UTXO should remain unspent after rug-pull, premature claim, and forged witness")
	}

	// 5. Alternate valid L2 burn slot (slot 3) also recovers Depositor's identical partial PSBT.
	wValid3, err := bqs.BridgeBurnWitness(3, secrets[3])
	if err != nil {
		t.Fatal(err)
	}
	decAlt, err := praxis.Dec(pp, ct, wValid3)
	if err != nil || !bytes.Equal(decAlt, expectedPSBT) {
		t.Fatalf("alternate slot witness failed to recover exact partial PSBT (err=%v)", err)
	}

	// 6. Primary valid witness (slot 1) decrypts Depositor's partial PSBT; Claimer co-signs
	//    the 2nd Schnorr signature (with Depositor completely untouched), finalizes the
	//    4-element OP_CHECKSIGADD Tapscript witness, broadcasts, and mines on Signet.
	recoveredPSBT, _, err := praxis.DecDetailed(pp, ct, wValid1)
	if err != nil {
		t.Fatalf("DecDetailed: %v", err)
	}
	settle, err := env.CoSignAndSweep(vault, recoveredPSBT)
	if err != nil {
		t.Fatalf("CoSignAndSweep: %v", err)
	}
	if settle.SweepTxID != vault.ExpectedSweepTxID {
		t.Fatalf("sweep txid %s != expected txid %s", settle.SweepTxID, vault.ExpectedSweepTxID)
	}
	if settle.WitnessItems != 4 {
		t.Fatalf("expected 4 witness items [sig_clm, sig_dep, tapscript, control_block], got %d", settle.WitnessItems)
	}
	if !settle.VaultSpent || settle.RecipientSats != VaultWithdrawSats {
		t.Fatalf("unexpected settlement state: %+v", settle)
	}
}
