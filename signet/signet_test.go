package signet

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
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
	csvEarly, err := env.AttemptPrematureCSVRefund(vault)
	if err != nil {
		t.Fatalf("AttemptPrematureCSVRefund: %v", err)
	}
	if !csvEarly.LeafFinalized || csvEarly.MempoolAllowed || !strings.Contains(csvEarly.RejectReason, "BIP68") {
		t.Fatalf("expected premature Leaf-2 CSV refund to be rejected with non-BIP68-final, got %+v", csvEarly)
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

	// 7. Test Leaf-2 OP_CHECKSEQUENCEVERIFY timeout refund on a second vault when Claimer ghosts:
	//    rejected before 6 confirmations (non-BIP68-final), accepted & settled once 6 blocks pass!
	ghostVault, err := env.LockTaprootVault()
	if err != nil {
		t.Fatalf("LockTaprootVault (ghost vault): %v", err)
	}
	earlyRefund, err := env.AttemptPrematureCSVRefund(ghostVault)
	if err != nil {
		t.Fatalf("AttemptPrematureCSVRefund (ghost vault): %v", err)
	}
	if earlyRefund.MempoolAllowed || !strings.Contains(earlyRefund.RejectReason, "BIP68") {
		t.Fatalf("expected non-BIP68-final before %d blocks, got %+v", VaultCSVBlocks, earlyRefund)
	}
	if _, _, err := env.MineBlocks(int(VaultCSVBlocks) - 1); err != nil {
		t.Fatalf("MineBlocks for CSV expiry: %v", err)
	}
	refundSettle, err := env.ExecuteCSVRefund(ghostVault)
	if err != nil {
		t.Fatalf("ExecuteCSVRefund after %d confirmations: %v", VaultCSVBlocks, err)
	}
	if refundSettle.WitnessItems != 3 {
		t.Fatalf("expected 3 witness items [sig_dep_refund, csv_script, control_block] on Leaf 2, got %d", refundSettle.WitnessItems)
	}
	if !refundSettle.VaultSpent || refundSettle.RecipientSats != VaultWithdrawSats {
		t.Fatalf("unexpected CSV refund settlement: %+v", refundSettle)
	}
}

func TestVaultConfigAndHelpers(t *testing.T) {
	defCfg, err := normalizeVaultConfig(VaultConfig{})
	if err != nil {
		t.Fatalf("normalizeVaultConfig(default): %v", err)
	}
	if defCfg.CSVBlocks != VaultCSVBlocks || defCfg.DepositSats != VaultDepositSats || defCfg.BaseFeeSats != VaultFeeSats || defCfg.EnableTRUCAnchor {
		t.Fatalf("unexpected default normalized config: %+v", defCfg)
	}

	trucCfg, err := normalizeVaultConfig(VaultConfig{EnableTRUCAnchor: true, CSVBlocks: 144})
	if err != nil {
		t.Fatalf("normalizeVaultConfig(truc): %v", err)
	}
	if trucCfg.CSVBlocks != 144 || trucCfg.DepositSats != VaultDepositSats || trucCfg.BaseFeeSats != 0 || !trucCfg.EnableTRUCAnchor {
		t.Fatalf("unexpected TRUC normalized config: %+v", trucCfg)
	}

	badConfigs := []VaultConfig{
		{CSVBlocks: 70_000},
		{DepositSats: -1},
		{BaseFeeSats: -10},
		{DepositSats: 1_000, BaseFeeSats: 900, EnableTRUCAnchor: true},
	}
	for i, bad := range badConfigs {
		if _, err := normalizeVaultConfig(bad); err == nil {
			t.Fatalf("case %d (%+v): expected validation error, got nil", i, bad)
		}
	}

	if got := formatBTC(0); got != "0.00000000" {
		t.Fatalf("formatBTC(0) = %q", got)
	}
	if got := formatBTC(15_000); got != "0.00015000" {
		t.Fatalf("formatBTC(15000) = %q", got)
	}
	if got := formatBTC(VaultDepositSats); got != "1.00000000" {
		t.Fatalf("formatBTC(1 BTC) = %q", got)
	}
	if got := csvBlocksForVault(nil); got != VaultCSVBlocks {
		t.Fatalf("csvBlocksForVault(nil) = %d, want %d", got, VaultCSVBlocks)
	}
	if got := csvBlocksForVault(&LockedVault{CSVBlocks: 12}); got != 12 {
		t.Fatalf("csvBlocksForVault(12) = %d, want 12", got)
	}

	patched, err := setRawTxVersion("02000000000000000000", uint32(TRUCTxVersion))
	if err != nil || patched != "03000000000000000000" {
		t.Fatalf("setRawTxVersion = %q, %v; want 03000000000000000000", patched, err)
	}
	if _, err := setRawTxVersion("0200", 3); err == nil {
		t.Fatalf("expected short raw tx error")
	}

	// Verify extractPSBTTxIDAndFirstTapSig selects the multi_a(2) Leaf-1 sig even
	// when Leaf 2's refund signature appears first in taproot_script_path_sigs.
	leaf1Script := "20" + strings.Repeat("11", 32) + "ac20" + strings.Repeat("22", 32) + "ba529c"
	leaf2Script := "20" + strings.Repeat("33", 32) + "ad56b2"
	l1Bytes, _ := hex.DecodeString(leaf1Script)
	l2Bytes, _ := hex.DecodeString(leaf2Script)
	l1Hash := bip341TapLeafHash(0xc0, l1Bytes)
	l2Hash := bip341TapLeafHash(0xc0, l2Bytes)
	mockPSBT := map[string]any{
		"tx": map[string]any{"txid": "abcd"},
		"inputs": []any{
			map[string]any{
				"taproot_scripts": []any{
					map[string]any{"script": leaf2Script, "leaf_ver": float64(0xc0)},
					map[string]any{"script": leaf1Script, "leaf_ver": float64(0xc0)},
				},
				"taproot_script_path_sigs": []any{
					map[string]any{"leaf_hash": reverseHexBytes(l2Hash[:]), "sig": strings.Repeat("aa", 64)},
					map[string]any{"leaf_hash": reverseHexBytes(l1Hash[:]), "sig": strings.Repeat("bb", 64)},
				},
			},
		},
	}
	gotTxID, gotSig := extractPSBTTxIDAndFirstTapSig(mockPSBT)
	if gotTxID != "abcd" || gotSig != strings.Repeat("bb", 64) {
		t.Fatalf("extractPSBTTxIDAndFirstTapSig picked wrong leaf sig: txid=%q sig=%q", gotTxID, gotSig)
	}
}

func connectTestSignet(t *testing.T) *Env {
	t.Helper()
	if os.Getenv("PRAXIS_SIGNET_DIR") == "" {
		if _, err := FindBitcoind(false); err != nil {
			t.Skipf("bitcoind not installed locally and PRAXIS_SIGNET_DIR unset: %v", err)
		}
	}
	env, err := ConnectAttachOrStart("", "")
	if err != nil {
		t.Fatalf("ConnectAttachOrStart: %v", err)
	}
	t.Cleanup(func() { _ = env.Close() })
	return env
}

func TestConfigurableCSVTimelockSignet(t *testing.T) {
	env := connectTestSignet(t)

	const csvTarget uint32 = 12
	vault, err := env.LockTaprootVaultWithConfig(VaultConfig{
		CSVBlocks: csvTarget,
	})
	if err != nil {
		t.Fatalf("LockTaprootVaultWithConfig(CSVBlocks=12): %v", err)
	}
	if vault.CSVBlocks != csvTarget {
		t.Fatalf("vault.CSVBlocks = %d, want %d", vault.CSVBlocks, csvTarget)
	}

	// Verify Depositor's real Bitcoin Core PSBT contains the multi_a(2) Leaf-1
	// script ending in OP_CHECKSIGADD OP_2 OP_NUMEQUAL (ba529c) and that
	// vault.DepositorSigHex matched that exact Leaf-1 TapLeaf hash.
	var decodedDepPSBT struct {
		Inputs []struct {
			TaprootScripts []struct {
				Script  string `json:"script"`
				LeafVer byte   `json:"leaf_ver"`
			} `json:"taproot_scripts"`
			TaprootSigs []struct {
				LeafHash string `json:"leaf_hash"`
				Sig      string `json:"sig"`
			} `json:"taproot_script_path_sigs"`
		} `json:"inputs"`
	}
	if err := env.Primary.Call("", "decodepsbt", []any{base64.StdEncoding.EncodeToString(vault.DepositorPartialPSBT)}, &decodedDepPSBT); err != nil {
		t.Fatalf("decodepsbt depositor partial PSBT: %v", err)
	}
	if len(decodedDepPSBT.Inputs) == 0 {
		t.Fatalf("expected >=1 PSBT input")
	}
	var matchedLeaf1Sig bool
	for _, sc := range decodedDepPSBT.Inputs[0].TaprootScripts {
		if !strings.HasSuffix(strings.ToLower(sc.Script), "ba529c") {
			continue
		}
		scBytes, err := hex.DecodeString(sc.Script)
		if err != nil {
			t.Fatalf("decode taproot leaf1 script: %v", err)
		}
		lh := bip341TapLeafHash(sc.LeafVer, scBytes)
		fwd, rev := hex.EncodeToString(lh[:]), reverseHexBytes(lh[:])
		for _, sigEntry := range decodedDepPSBT.Inputs[0].TaprootSigs {
			lhLower := strings.ToLower(sigEntry.LeafHash)
			if (lhLower == fwd || lhLower == rev) && strings.EqualFold(sigEntry.Sig, vault.DepositorSigHex) {
				matchedLeaf1Sig = true
			}
		}
	}
	if !matchedLeaf1Sig {
		t.Fatalf("vault.DepositorSigHex (%s) did not match multi_a(2) ba529c Leaf-1 TapLeaf hash in real decoded PSBT: %+v",
			vault.DepositorSigHex, decodedDepPSBT.Inputs[0])
	}
	if vault.TRUCAnchorEnabled || vault.AnchorVout != -1 {
		t.Fatalf("expected TRUC disabled on CSV-only vault, got enabled=%v anchorVout=%d", vault.TRUCAnchorEnabled, vault.AnchorVout)
	}
	if !strings.Contains(vault.PublicDescriptor, "older(12)") {
		t.Fatalf("expected descriptor to contain older(12), got %s", vault.PublicDescriptor)
	}

	// At 1 confirmation: must be rejected with non-BIP68-final.
	att1, err := env.AttemptPrematureCSVRefund(vault)
	if err != nil {
		t.Fatalf("AttemptPrematureCSVRefund at 1 conf: %v", err)
	}
	if !att1.LeafFinalized || att1.MempoolAllowed || att1.CSVBlocks != csvTarget || !strings.Contains(att1.RejectReason, "non-BIP68-final") {
		t.Fatalf("expected non-BIP68-final at 1 conf, got %+v", att1)
	}

	// Mine 5 blocks -> 6 confirmations (old default): MUST STILL be rejected!
	if _, _, err := env.MineBlocks(5); err != nil {
		t.Fatalf("MineBlocks(5): %v", err)
	}
	att6, err := env.AttemptPrematureCSVRefund(vault)
	if err != nil {
		t.Fatalf("AttemptPrematureCSVRefund at 6 confs: %v", err)
	}
	if att6.MempoolAllowed || !strings.Contains(att6.RejectReason, "non-BIP68-final") {
		t.Fatalf("expected non-BIP68-final at 6 confs for CSV=12 vault, got %+v", att6)
	}

	// Mine 5 more blocks -> 11 confirmations: MUST STILL be rejected!
	if _, _, err := env.MineBlocks(5); err != nil {
		t.Fatalf("MineBlocks(5) to 11 confs: %v", err)
	}
	att11, err := env.AttemptPrematureCSVRefund(vault)
	if err != nil {
		t.Fatalf("AttemptPrematureCSVRefund at 11 confs: %v", err)
	}
	if att11.MempoolAllowed || !strings.Contains(att11.RejectReason, "non-BIP68-final") {
		t.Fatalf("expected non-BIP68-final at 11 confs for CSV=12 vault, got %+v", att11)
	}

	// Mine 1 more block -> 12 confirmations: Leaf-2 CSV refund succeeds!
	if _, _, err := env.MineBlocks(1); err != nil {
		t.Fatalf("MineBlocks(1) to 12 confs: %v", err)
	}
	refundSettle, err := env.ExecuteCSVRefund(vault)
	if err != nil {
		t.Fatalf("ExecuteCSVRefund at 12 confs: %v", err)
	}
	if refundSettle.WitnessItems != 3 {
		t.Fatalf("expected 3 witness items on Leaf-2 CSV refund, got %d", refundSettle.WitnessItems)
	}
	if !refundSettle.VaultSpent || refundSettle.RecipientSats != VaultWithdrawSats {
		t.Fatalf("unexpected CSV=12 refund settlement: %+v", refundSettle)
	}
	t.Logf("CSV=12 verified on Signet (%s): rejected at 1/6/11 confs (%s), settled at height %d refund_txid=%s",
		env.Mode, att6.RejectReason, refundSettle.BlockHeight, refundSettle.SweepTxID)
}

func TestTRUCv3P2ACPFPSweepSignet(t *testing.T) {
	env := connectTestSignet(t)

	const csvTarget uint32 = 12
	const bumpFeeSats int64 = 15_000
	vault, err := env.LockTaprootVaultWithConfig(VaultConfig{
		CSVBlocks:        csvTarget,
		EnableTRUCAnchor: true,
		DepositSats:      VaultDepositSats,
		BaseFeeSats:      0,
	})
	if err != nil {
		t.Fatalf("LockTaprootVaultWithConfig(TRUC+P2A): %v", err)
	}
	if !vault.TRUCAnchorEnabled || vault.AnchorVout != 1 {
		t.Fatalf("expected TRUCAnchorEnabled=true AnchorVout=1, got %v / %d", vault.TRUCAnchorEnabled, vault.AnchorVout)
	}
	if vault.FeeSats != 0 || vault.WithdrawSats != VaultDepositSats {
		t.Fatalf("expected 0-sat base fee and full %d sat payout, got fee=%d withdraw=%d",
			VaultDepositSats, vault.FeeSats, vault.WithdrawSats)
	}
	if vault.CSVBlocks != csvTarget {
		t.Fatalf("vault.CSVBlocks = %d, want %d", vault.CSVBlocks, csvTarget)
	}

	// Verify Depositor's real Bitcoin Core PSBT contains the multi_a(2) Leaf-1
	// script ending in OP_CHECKSIGADD OP_2 OP_NUMEQUAL (ba529c) and that
	// vault.DepositorSigHex matched that exact Leaf-1 TapLeaf hash.
	var decodedDepPSBT struct {
		Inputs []struct {
			TaprootScripts []struct {
				Script  string `json:"script"`
				LeafVer byte   `json:"leaf_ver"`
			} `json:"taproot_scripts"`
			TaprootSigs []struct {
				LeafHash string `json:"leaf_hash"`
				Sig      string `json:"sig"`
			} `json:"taproot_script_path_sigs"`
		} `json:"inputs"`
	}
	if err := env.Primary.Call("", "decodepsbt", []any{base64.StdEncoding.EncodeToString(vault.DepositorPartialPSBT)}, &decodedDepPSBT); err != nil {
		t.Fatalf("decodepsbt depositor partial PSBT: %v", err)
	}
	if len(decodedDepPSBT.Inputs) == 0 {
		t.Fatalf("expected >=1 PSBT input")
	}
	var matchedLeaf1Sig bool
	for _, sc := range decodedDepPSBT.Inputs[0].TaprootScripts {
		if !strings.HasSuffix(strings.ToLower(sc.Script), "ba529c") {
			continue
		}
		scBytes, err := hex.DecodeString(sc.Script)
		if err != nil {
			t.Fatalf("decode taproot leaf1 script: %v", err)
		}
		lh := bip341TapLeafHash(sc.LeafVer, scBytes)
		fwd, rev := hex.EncodeToString(lh[:]), reverseHexBytes(lh[:])
		for _, sigEntry := range decodedDepPSBT.Inputs[0].TaprootSigs {
			lhLower := strings.ToLower(sigEntry.LeafHash)
			if (lhLower == fwd || lhLower == rev) && strings.EqualFold(sigEntry.Sig, vault.DepositorSigHex) {
				matchedLeaf1Sig = true
			}
		}
	}
	if !matchedLeaf1Sig {
		t.Fatalf("vault.DepositorSigHex (%s) did not match multi_a(2) ba529c Leaf-1 TapLeaf hash in real decoded PSBT: %+v",
			vault.DepositorSigHex, decodedDepPSBT.Inputs[0])
	}

	// Verify unilateral spend & premature CSV still fail on TRUC vault.
	depRug, err := env.AttemptUnilateralSpend(vault, "depositor")
	if err != nil || depRug.FinalizableAlone || !depRug.PartialSigned {
		t.Fatalf("unexpected depositor unilateral attempt on TRUC vault: %+v err=%v", depRug, err)
	}
	clmEarly, err := env.AttemptUnilateralSpend(vault, "claimer")
	if err != nil || clmEarly.FinalizableAlone || !clmEarly.PartialSigned {
		t.Fatalf("unexpected claimer unilateral attempt on TRUC vault: %+v err=%v", clmEarly, err)
	}
	csvEarly, err := env.AttemptPrematureCSVRefund(vault)
	if err != nil || csvEarly.MempoolAllowed || !strings.Contains(csvEarly.RejectReason, "non-BIP68-final") {
		t.Fatalf("expected premature CSV rejection on TRUC vault, got %+v err=%v", csvEarly, err)
	}

	// Seal Depositor's TRUC v3 + P2A partial PSBT inside Praxis witness encryption and recover it.
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
	ct, _, err := praxis.EncDetailed(pp, vault.DepositorPartialPSBT)
	if err != nil {
		t.Fatalf("praxis.EncDetailed: %v", err)
	}
	for i := range vault.DepositorPartialPSBT {
		vault.DepositorPartialPSBT[i] = 0
	}
	wValid, err := bqs.BridgeBurnWitness(1, secrets[1])
	if err != nil {
		t.Fatal(err)
	}
	recoveredPSBT, _, err := praxis.DecDetailed(pp, ct, wValid)
	if err != nil {
		t.Fatalf("praxis.DecDetailed: %v", err)
	}

	// Prove the standalone 0-fee TRUC v3 + P2A parent FAILS testmempoolaccept alone
	// with "min relay fee not met", demonstrating CPFP package relay actually carries it.
	parentHex, parentTxID, witnessItems, err := env.CoSignFinalizeOnly(vault, recoveredPSBT)
	if err != nil {
		t.Fatalf("CoSignFinalizeOnly: %v", err)
	}
	if parentTxID != vault.ExpectedSweepTxID || witnessItems != 4 {
		t.Fatalf("unexpected finalized parent: txid=%s expected=%s witnessItems=%d", parentTxID, vault.ExpectedSweepTxID, witnessItems)
	}
	aloneRes, err := env.TestMempoolAccept(parentHex)
	if err != nil {
		t.Fatalf("TestMempoolAccept standalone parent: %v", err)
	}
	if len(aloneRes) != 1 || aloneRes[0].Allowed || !strings.Contains(aloneRes[0].RejectReason, "min relay fee not met") {
		t.Fatalf("expected standalone 0-fee TRUC parent to fail with 'min relay fee not met', got %+v", aloneRes)
	}

	// Submit [parent, child] atomically via submitpackage + mine 1 block!
	settle, err := env.CoSignSweepWithCPFP(vault, recoveredPSBT, bumpFeeSats)
	if err != nil {
		t.Fatalf("CoSignSweepWithCPFP: %v", err)
	}
	if settle.SweepTxID != vault.ExpectedSweepTxID {
		t.Fatalf("parent txid %s != expected %s", settle.SweepTxID, vault.ExpectedSweepTxID)
	}
	if settle.ChildTxID == "" || settle.ChildTxID == settle.SweepTxID || !settle.ChildConfirmed {
		t.Fatalf("expected confirmed distinct CPFP child tx, got %+v", settle)
	}
	if settle.WitnessItems != 4 || !settle.VaultSpent {
		t.Fatalf("unexpected parent witness/spent state: %+v", settle)
	}
	if settle.RecipientSats != VaultDepositSats {
		t.Fatalf("expected full %d sat Claimer payout, got %d", VaultDepositSats, settle.RecipientSats)
	}
	if settle.PackageFeeSats != bumpFeeSats || settle.PackageFeeRateSatPerV <= 0 {
		t.Fatalf("unexpected package fee stats: %+v", settle)
	}

	// Cross-check confirmed on-chain parent & child raw transactions via RPC.
	var parentChain struct {
		Version   int    `json:"version"`
		BlockHash string `json:"blockhash"`
		Vout      []struct {
			Value        float64 `json:"value"`
			ScriptPubKey struct {
				Hex     string `json:"hex"`
				Type    string `json:"type"`
				Address string `json:"address"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	if err := env.Primary.Call("", "getrawtransaction", []any{settle.SweepTxID, true}, &parentChain); err != nil {
		t.Fatalf("getrawtransaction parent: %v", err)
	}
	if parentChain.Version != TRUCTxVersion || parentChain.BlockHash != settle.BlockHash {
		t.Fatalf("parent on-chain mismatch: version=%d blockhash=%s wantBlock=%s", parentChain.Version, parentChain.BlockHash, settle.BlockHash)
	}
	if len(parentChain.Vout) != 2 || parentChain.Vout[1].ScriptPubKey.Hex != P2AScriptPubKey || parentChain.Vout[1].ScriptPubKey.Type != "anchor" {
		t.Fatalf("unexpected parent outputs on chain: %+v", parentChain.Vout)
	}

	var childChain struct {
		Version   int    `json:"version"`
		BlockHash string `json:"blockhash"`
		Vin       []struct {
			TxID        string   `json:"txid"`
			Vout        int      `json:"vout"`
			TxInWitness []string `json:"txinwitness"`
		} `json:"vin"`
	}
	if err := env.Primary.Call("", "getrawtransaction", []any{settle.ChildTxID, true}, &childChain); err != nil {
		t.Fatalf("getrawtransaction child: %v", err)
	}
	if childChain.Version != TRUCTxVersion || childChain.BlockHash != settle.BlockHash {
		t.Fatalf("child on-chain mismatch: version=%d blockhash=%s wantBlock=%s", childChain.Version, childChain.BlockHash, settle.BlockHash)
	}
	if len(childChain.Vin) != 2 || childChain.Vin[0].TxID != settle.SweepTxID || childChain.Vin[0].Vout != 1 || len(childChain.Vin[0].TxInWitness) != 0 {
		t.Fatalf("expected child vin[0] to spend parent:1 with empty witness [], got %+v", childChain.Vin)
	}

	t.Logf("TRUC v3 + P2A CPFP verified on Signet (%s): standalone_reject=%q parent_txid=%s (%d vB) child_txid=%s (%d vB) pkg_fee=%d sats (%.2f sat/vB) block=%d payout=%d sats peer_synced=%v",
		env.Mode, aloneRes[0].RejectReason, settle.SweepTxID, settle.ParentVSize, settle.ChildTxID, settle.ChildVSize,
		settle.PackageFeeSats, settle.PackageFeeRateSatPerV, settle.BlockHeight, settle.RecipientSats, settle.PeerSynced)
}
