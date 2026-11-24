// Command praxis encrypts a message to a puzzle and decrypts it with the
// puzzle's solution, including an operator-free 2-of-2 Bitcoin Private Signet
// Taproot vault bridge demo. It is a demonstration and is not secure.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"praxis-demo/bqs"
	"praxis-demo/praxis"
	"praxis-demo/signet"
	"praxis-demo/tui"
)

const usage = `praxis: witness encryption demo. NOT SECURE; do not protect anything with it.

  praxis tui [--toy]
      Open the interactive Charm TUI workbench (Toy & Advanced modes + Signet Bridge).

  praxis bridge [--toy] [--rpc 127.0.0.1:PORT --cookie PATH]
      Execute an end-to-end operator-free 2-of-2 Bitcoin Private Signet Taproot vault:
      fund 2-of-2 tr(NUMS, multi_a(2, Dep, Clm)) -> verify neither live key can spend alone
      -> Praxis-encrypt Depositor's 1-of-2 PSBT -> reject forged burn proof -> prove L2 burn
      -> decrypt, co-sign with Claimer, finalize OP_CHECKSIGADD, broadcast & mine on Signet.

  praxis demo [--advanced | --tui]
      Encrypt to puzzles and decrypt with their solutions.

  praxis encrypt [--advanced] factor <n> <bits> <message> <file>
      Encrypt to "n = p * q with p and q of at most <bits> bits".
  praxis decrypt <file> <p> <q>

  praxis encrypt [--advanced] colour <edges> <colours> <message> <file>
      Encrypt to "this graph can be coloured with <colours> colours".
      Edges look like 0-1,1-2,2-0.
  praxis decrypt <file> <colour of vertex 0>,<of vertex 1>,...
`

// puzzle is the statement a file is encrypted to, kept at the head of the
// file so that decryption can rebuild the system.
type puzzle struct {
	Kind     string   `json:"kind"`
	Advanced bool     `json:"advanced,omitempty"`
	N        string   `json:"n,omitempty"`
	Bits     int      `json:"bits,omitempty"`
	Vertices int      `json:"vertices,omitempty"`
	Colours  int      `json:"colours,omitempty"`
	Edges    [][2]int `json:"edges,omitempty"`
}

func (p puzzle) params() praxis.Params {
	if p.Advanced {
		return praxis.Advanced
	}
	return praxis.Toy
}

func (p puzzle) system() (*bqs.System, error) {
	var s *bqs.System
	var err error
	switch p.Kind {
	case "factor":
		n, ok := new(big.Int).SetString(p.N, 10)
		if !ok {
			return nil, fmt.Errorf("bad number %q", p.N)
		}
		s, err = bqs.Factoring(n, p.Bits, p.Bits)
	case "colour":
		s, err = bqs.Colouring(p.Vertices, p.Colours, p.Edges)
	default:
		return nil, fmt.Errorf("unknown puzzle kind %q", p.Kind)
	}
	if err != nil {
		return nil, err
	}
	return s.PadConstraints(p.params().JRem()), nil
}

func (p puzzle) String() string {
	if p.Kind == "factor" {
		return fmt.Sprintf("%s = p * q, with p and q of at most %d bits", p.N, p.Bits)
	}
	return fmt.Sprintf("a graph of %d vertices and %d edges has a colouring with %d colours",
		p.Vertices, len(p.Edges), p.Colours)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	switch {
	case len(args) == 1 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help"):
		fmt.Print(usage)
		return nil
	case len(args) == 1 && args[0] == "tui":
		return tui.Run(true)
	case len(args) == 2 && args[0] == "tui" && args[1] == "--toy":
		return tui.Run(false)
	case len(args) >= 1 && (args[0] == "bridge" || args[0] == "signet"):
		return runBridgeCLI(args[1:])
	case len(args) == 1 && args[0] == "demo":
		return demo(false)
	case len(args) == 2 && args[0] == "demo" && args[1] == "--advanced":
		return demo(true)
	case len(args) == 2 && args[0] == "demo" && args[1] == "--tui":
		return tui.Run(true)
	case len(args) >= 6 && args[0] == "encrypt":
		adv := false
		rest := args[1:]
		if len(rest) == 6 && rest[0] == "--advanced" {
			adv = true
			rest = rest[1:]
		}
		if len(rest) == 5 && rest[0] == "factor" {
			bits, err := strconv.Atoi(rest[2])
			if err != nil {
				return err
			}
			return encrypt(puzzle{Kind: "factor", Advanced: adv, N: rest[1], Bits: bits}, rest[3], rest[4])
		}
		if len(rest) == 5 && rest[0] == "colour" {
			p := puzzle{Kind: "colour", Advanced: adv}
			for _, e := range strings.Split(rest[1], ",") {
				left, right, ok := strings.Cut(e, "-")
				if !ok {
					return fmt.Errorf("bad edge %q", e)
				}
				a, err1 := strconv.Atoi(left)
				b, err2 := strconv.Atoi(right)
				if err1 != nil || err2 != nil || a < 0 || b < 0 || a > 1<<20 || b > 1<<20 {
					return fmt.Errorf("bad edge %q", e)
				}
				p.Edges = append(p.Edges, [2]int{a, b})
				p.Vertices = max(p.Vertices, a+1, b+1)
			}
			var err error
			if p.Colours, err = strconv.Atoi(rest[2]); err != nil {
				return err
			}
			return encrypt(p, rest[3], rest[4])
		}
	case len(args) >= 3 && args[0] == "decrypt":
		return decrypt(args[1], args[2:])
	}
	fmt.Fprint(os.Stderr, usage)
	return fmt.Errorf("invalid arguments")
}

func runBridgeCLI(args []string) error {
	advanced := true
	var rpcHost, cookiePath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--toy":
			advanced = false
		case "--advanced":
			advanced = true
		case "--rpc":
			if i+1 >= len(args) {
				return fmt.Errorf("--rpc requires host:port")
			}
			i++
			rpcHost = args[i]
		case "--cookie":
			if i+1 >= len(args) {
				return fmt.Errorf("--cookie requires file path")
			}
			i++
			cookiePath = args[i]
		default:
			return fmt.Errorf("unknown bridge flag %q", args[i])
		}
	}

	par := praxis.Advanced
	modeLabel := "ADVANCED (n=24 Serret, 36 cells, J=4/J'=2 chunks, FFT QAP, outward sign-FP64)"
	if !advanced {
		par = praxis.Toy
		modeLabel = "TOY (n=8, 12 cells, J=1/J'=1, schoolbook QAP, growing-interval BSGS)"
	}

	fmt.Printf("Praxis Operator-Free 2-of-2 Bitcoin Signet Vault Demo — %s\n", modeLabel)
	fmt.Println("WARNING: Research prototype at demo parameters; NOT constant-time or production-secure.")
	fmt.Println()

	env, err := signet.ConnectAttachOrStart(rpcHost, cookiePath)
	if err != nil {
		return err
	}
	defer env.Close()

	st0, err := env.Status()
	if err != nil {
		return err
	}
	peerNote := ""
	if st0.PeerRPC != "" && st0.PeerHeight >= 0 {
		peerNote = fmt.Sprintf(", peer %s @ #%d", st0.PeerRPC, st0.PeerHeight)
	}
	fmt.Printf("[1/6] Connected to Private Signet (%s: %s @ #%d%s)\n",
		st0.Mode, st0.PrimaryRPC, st0.Height, peerNote)

	vault, err := env.LockTaprootVault()
	if err != nil {
		return err
	}
	fmt.Printf("[2/6] Funded 2-of-2 Tapscript Vault — tr(NUMS, multi_a(2, Depositor, Claimer))\n")
	fmt.Printf("      Vault P2TR:        %s\n", vault.VaultAddress)
	fmt.Printf("      Deposit OutPoint:  %s (%.8f sBTC, mined in block #%d)\n",
		vault.OutPoint(), float64(vault.DepositSats)/1e8, vault.DepositBlock)
	fmt.Printf("      Claimer Recipient: %s (%.8f sBTC, fee %d sats)\n",
		vault.RecipientAddress, float64(vault.WithdrawSats)/1e8, vault.FeeSats)
	fmt.Printf("      Key Custody:       BOTH Depositor & Claimer private keys remain LIVE (no key deletion trusted)\n")
	fmt.Printf("      Depositor 1/2 PSBT:%d bytes (BIP-340 Schnorr share %s...)\n",
		len(vault.DepositorPartialPSBT), vault.DepositorSigHex[:24])

	depRug, err := env.AttemptUnilateralSpend(vault, "depositor")
	if err != nil {
		return err
	}
	clmEarly, err := env.AttemptUnilateralSpend(vault, "claimer")
	if err != nil {
		return err
	}
	if depRug.FinalizableAlone || clmEarly.FinalizableAlone {
		return fmt.Errorf("unexpected unilateral spend succeeded")
	}
	fmt.Printf("[3/6] Verified Live-Key Unilateral Spend Resistance on Bitcoin Core\n")
	fmt.Printf("      Depositor rug-pull (live key): 1-of-2 signed=%v, finalizable alone=%v -> BLOCKED\n",
		depRug.PartialSigned, depRug.FinalizableAlone)
	fmt.Printf("      Claimer early take (live key): 1-of-2 signed=%v, finalizable alone=%v -> BLOCKED\n",
		clmEarly.PartialSigned, clmEarly.FinalizableAlone)

	ctx := bqs.BridgeContext{
		VaultOutPoint:    vault.OutPoint(),
		RecipientAddress: vault.RecipientAddress,
		AmountSats:       vault.WithdrawSats,
	}
	var secrets [bqs.BridgeBatchSlots][16]byte
	for i := range secrets {
		if _, err := rand.Read(secrets[i][:]); err != nil {
			return err
		}
	}
	var batch [bqs.BridgeBatchSlots]bqs.BridgeNoteCommitment
	for i := range batch {
		batch[i] = bqs.CommitBridgeBurn(ctx, secrets[i])
	}
	rawSys, err := bqs.BridgeBurn(ctx, batch)
	if err != nil {
		return err
	}
	pp, err := praxis.Setup(par, rawSys.PadConstraints(par.JRem()))
	if err != nil {
		return err
	}
	ct, encRep, err := praxis.EncDetailed(pp, vault.DepositorPartialPSBT)
	for i := range vault.DepositorPartialPSBT {
		vault.DepositorPartialPSBT[i] = 0
	}
	vault.DepositorPartialPSBT = nil
	if err != nil {
		return err
	}
	fmt.Printf("[4/6] Sealed Depositor's 1-of-2 Partial PSBT inside Praxis Ciphertext (Depositor now offline)\n")
	fmt.Printf("      BQS Statement:     N=%d unknowns, nc=%d equations, nu=%d cosets (|H|=%d)\n",
		pp.S.N, len(pp.S.Constraints), pp.Nu, pp.SubgroupSize)
	fmt.Printf("      Ciphertext:        %d bytes (%d G1 + %d G2, chunks J=%d/%d, J'=%d/%d) in %v\n",
		encRep.Bytes, encRep.G1, encRep.G2, encRep.J, encRep.Delta, encRep.JPrime, encRep.DeltaP,
		encRep.EncDur.Round(time.Millisecond))

	// Attack with forged burn proof before legitimate withdrawal.
	w1, err := bqs.BridgeBurnWitness(1, secrets[1])
	if err != nil {
		return err
	}
	forged := append([]bool(nil), w1...)
	forged[5] = !forged[5]
	badOut, badRep, badErr := praxis.DecUncheckedDetailed(pp, ct, forged)
	unspentAfterAttack, err := env.IsOutPointUnspent(vault.DepositTxID, vault.DepositVout)
	if err != nil {
		return err
	}
	fmt.Printf("[5/6] Forged Burn-Proof Attack (1 bit flipped in DecUnchecked)\n")
	fmt.Printf("      Praxis Result:     %s (exact QAP=%v, %v)\n",
		describe(badOut, badErr), badRep.ExactQAP, badRep.TotalDur.Round(time.Millisecond))
	fmt.Printf("      Signet UTXO:       unspent = %v (1.00000000 sBTC remains locked in 2-of-2)\n", unspentAfterAttack)

	// Prove valid L2 burn slot #1 -> decrypt Depositor's 1/2 PSBT -> Claimer co-signs & sweeps.
	recoveredPSBT, decRep, err := praxis.DecDetailed(pp, ct, w1)
	if err != nil {
		return fmt.Errorf("valid burn proof decryption failed: %w", err)
	}
	settle, err := env.CoSignAndSweep(vault, recoveredPSBT)
	if err != nil {
		return err
	}
	peerConfirm := ""
	if settle.PeerBlockHeight >= 0 {
		peerConfirm = fmt.Sprintf(" (peer synced=%v @ #%d)", settle.PeerSynced, settle.PeerBlockHeight)
	}
	fmt.Printf("[6/6] Valid L2 Burn Proof (Slot #1, secret %s…) -> Co-Signed & Settled\n",
		hex.EncodeToString(secrets[1][:])[:16])
	fmt.Printf("      Praxis Decrypt:    %v (%d pairings, %s baby=%d giant=%d, offset t=%s)\n",
		decRep.TotalDur.Round(time.Millisecond), decRep.Pairings, decRep.Search.Algorithm,
		decRep.Search.BabySteps, decRep.Search.GiantSteps, decRep.Search.Offset.String())
	fmt.Printf("      Claimer Co-Sign:   OP_CHECKSIGADD finalized (%d witness items, %d B tx, Depositor offline)\n",
		settle.WitnessItems, settle.TxBytes)
	fmt.Printf("      Broadcast TxID:    %s (matches expected=%v)\n",
		settle.SweepTxID, settle.SweepTxID == vault.ExpectedSweepTxID)
	fmt.Printf("      Confirmed Block:   #%d (%s)%s\n",
		settle.BlockHeight, settle.BlockHash, peerConfirm)
	fmt.Printf("      Final Balances:    Vault UTXO spent = %v | Claimer %s = %.8f sBTC\n",
		settle.VaultSpent, vault.RecipientAddress, float64(settle.RecipientSats)/1e8)
	return nil
}

func encrypt(p puzzle, msg, file string) error {
	s, err := p.system()
	if err != nil {
		return err
	}
	pp, err := praxis.Setup(p.params(), s)
	if err != nil {
		return err
	}
	ct, err := praxis.Enc(pp, []byte(msg))
	if err != nil {
		return err
	}
	head, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(head)))
	buf.Write(head)
	if _, err := ct.WriteTo(&buf); err != nil {
		return err
	}
	if err := os.WriteFile(file, buf.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("encrypted to: %s\n%s: %d bytes, %d unknowns\n", p, file, buf.Len(), s.N)
	return nil
}

func decrypt(file string, sol []string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	var hl uint32
	if err := binary.Read(f, binary.BigEndian, &hl); err != nil || hl > 1<<20 {
		return fmt.Errorf("%s is not a praxis-demo file", file)
	}
	head := make([]byte, hl)
	if _, err := io.ReadFull(f, head); err != nil {
		return err
	}
	var p puzzle
	if err := json.Unmarshal(head, &p); err != nil {
		return err
	}
	s, err := p.system()
	if err != nil {
		return err
	}
	var w []bool
	switch p.Kind {
	case "factor":
		if len(sol) != 2 {
			return fmt.Errorf("give the two factors p and q")
		}
		a, ok1 := new(big.Int).SetString(sol[0], 10)
		b, ok2 := new(big.Int).SetString(sol[1], 10)
		if !ok1 || !ok2 || a.Sign() < 0 || b.Sign() < 0 || a.BitLen() > p.Bits || b.BitLen() > p.Bits {
			return fmt.Errorf("the factors must be numbers of at most %d bits", p.Bits)
		}
		w = bqs.FactoringWitness(a, b, p.Bits, p.Bits)
	case "colour":
		parts := strings.Split(strings.Join(sol, ","), ",")
		if len(parts) != p.Vertices {
			return fmt.Errorf("give %d colours, one per vertex", p.Vertices)
		}
		colours := make([]int, len(parts))
		for i, c := range parts {
			v, err := strconv.Atoi(c)
			if err != nil || v < 0 || v >= p.Colours {
				return fmt.Errorf("colour %q is not from 0 to %d", c, p.Colours-1)
			}
			colours[i] = v
		}
		w = bqs.ColouringWitness(colours, p.Colours)
	}
	pp, err := praxis.Setup(p.params(), s)
	if err != nil {
		return err
	}
	ct, err := praxis.ReadCiphertext(f)
	if err != nil {
		return err
	}
	fmt.Printf("encrypted to: %s\n", p)
	msg, err := praxis.Dec(pp, ct, w)
	if err != nil {
		return err
	}
	fmt.Printf("message: %s\n", msg)
	return nil
}

func demo(advanced bool) error {
	par := praxis.Toy
	modeDesc := "toy parameters (n=8, J=1/J'=1, schoolbook QAP, growing-interval BSGS)"
	if advanced {
		par = praxis.Advanced
		modeDesc = "advanced parameters (n=24 Serret, 36 cells, J=4/J'=2 chunks, bit-rev FFT QAP, outward sign-FP64 search)"
	}
	fmt.Printf("Praxis witness encryption, %s. NOT SECURE.\n", modeDesc)
	p, q := big.NewInt(4294967291), big.NewInt(4294967279) // two primes just below 2^32
	fact := puzzle{Kind: "factor", Advanced: advanced, N: new(big.Int).Mul(p, q).String(), Bits: 32}
	col := puzzle{Kind: "colour", Advanced: advanced, Vertices: 10, Colours: 3, Edges: [][2]int{
		// The Petersen graph.
		{0, 1}, {1, 2}, {2, 3}, {3, 4}, {4, 0}, {0, 5}, {1, 6}, {2, 7},
		{3, 8}, {4, 9}, {5, 7}, {7, 9}, {9, 6}, {6, 8}, {8, 5}}}
	cases := []struct {
		p puzzle
		w func() []bool
	}{
		{fact, func() []bool { return bqs.FactoringWitness(p, q, 32, 32) }},
		{col, func() []bool { return bqs.ColouringWitness([]int{0, 1, 0, 1, 2, 1, 2, 2, 0, 0}, 3) }},
	}
	for _, c := range cases {
		s, err := c.p.system()
		if err != nil {
			return err
		}
		fmt.Printf("\nStatement: %s\n", c.p)
		fmt.Printf("  %d unknowns, %d equations\n", s.N, len(s.Constraints))
		pp, err := praxis.Setup(par, s)
		if err != nil {
			return err
		}
		msg := []byte("the solution was the key")
		ct, encRep, err := praxis.EncDetailed(pp, msg)
		if err != nil {
			return err
		}
		fmt.Printf("  encrypted in %v: %d bytes (%d + %d group elements, chunks J=%d/%d, J'=%d/%d)\n",
			encRep.EncDur.Round(time.Millisecond), ct.Size(), encRep.G1, encRep.G2,
			encRep.J, encRep.Delta, encRep.JPrime, encRep.DeltaP)

		w := c.w()
		got, decRep, err := praxis.DecDetailed(pp, ct, w)
		if err != nil {
			return err
		}
		fmt.Printf("  decrypted with the solution in %v: %q (search: %s, baby=%d, giant=%d)\n",
			decRep.TotalDur.Round(time.Millisecond), got,
			decRep.Search.Algorithm, decRep.Search.BabySteps, decRep.Search.GiantSteps)

		w[1] = !w[1]
		got, err = praxis.DecUnchecked(pp, ct, w)
		if err == nil && bytes.Equal(got, msg) {
			return fmt.Errorf("a wrong assignment decrypted the message")
		}
		fmt.Printf("  with one unknown flipped: %v\n", describe(got, err))
	}
	return nil
}

func describe(got []byte, err error) string {
	if err != nil {
		return "no key found"
	}
	return fmt.Sprintf("noise (%x...)", got[:min(6, len(got))])
}
