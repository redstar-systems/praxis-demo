// Package tui implements an interactive Charm v2 workbench for exploring Praxis
// witness encryption across Toy and Advanced (Figures 9–10) modes, including a
// live operator-free 2-of-2 Bitcoin Private Signet Taproot bridge vault.
package tui

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"praxis-demo/bqs"
	"praxis-demo/praxis"
	"praxis-demo/signet"
)

// SilkCircuit Neon palette (matching cherry-pi's surface/ink/accent hierarchy).
var (
	colBg     = lipgloss.Color("#12101a")
	colPane   = lipgloss.Color("#181425")
	colHeader = lipgloss.Color("#221e32")
	colRule   = lipgloss.Color("#39305c")
	colInk    = lipgloss.Color("#f8f8f2")
	colSub    = lipgloss.Color("#e9d5ff")
	colMuted  = lipgloss.Color("#768d8d")
	colPurple = lipgloss.Color("#e135ff")
	colCyan   = lipgloss.Color("#80ffea")
	colGreen  = lipgloss.Color("#50fa7b")
	colCoral  = lipgloss.Color("#ff6ac1")
	colRed    = lipgloss.Color("#ff6363")
	colYellow = lipgloss.Color("#f1fa8c")

	stTitle    = lipgloss.NewStyle().Foreground(colInk).Bold(true)
	stPurple   = lipgloss.NewStyle().Foreground(colPurple).Bold(true)
	stCyan     = lipgloss.NewStyle().Foreground(colCyan).Bold(true)
	stGreen    = lipgloss.NewStyle().Foreground(colGreen).Bold(true)
	stCoral    = lipgloss.NewStyle().Foreground(colCoral)
	stRed      = lipgloss.NewStyle().Foreground(colRed).Bold(true)
	stYellow   = lipgloss.NewStyle().Foreground(colYellow).Bold(true)
	stSub      = lipgloss.NewStyle().Foreground(colSub)
	stMuted    = lipgloss.NewStyle().Foreground(colMuted)
	stRule     = lipgloss.NewStyle().Foreground(colRule)
	stPillAdv  = lipgloss.NewStyle().Foreground(colBg).Background(colPurple).Bold(true).Padding(0, 1)
	stPillToy  = lipgloss.NewStyle().Foreground(colBg).Background(colCyan).Bold(true).Padding(0, 1)
	stPillWarn = lipgloss.NewStyle().Foreground(colYellow).Background(colHeader).Padding(0, 1)
)

// Scenario is one built-in NP statement with two distinct witnesses.
type Scenario struct {
	Name       string
	Tag        string
	Statement  string
	Message    string
	RawSys     *bqs.System
	Witness1   []bool
	Wit1Desc   string
	Witness2   []bool
	Wit2Desc   string
	LiveSignet bool
}

func buildScenarios() []Scenario {
	// 1. 64-bit semiprime factoring (R1CS, Fmax = 1).
	p, q := big.NewInt(4294967291), big.NewInt(4294967279)
	prod := new(big.Int).Mul(p, q)
	sFact, _ := bqs.Factoring(prod, 32, 32)
	wFact1 := bqs.FactoringWitness(p, q, 32, 32)
	wFact2 := bqs.FactoringWitness(q, p, 32, 32)

	// 2. Petersen graph 3-colouring (Coset BQS, Fmax = 3 -> nu = 4).
	edges := [][2]int{
		{0, 1}, {1, 2}, {2, 3}, {3, 4}, {4, 0},
		{0, 5}, {1, 6}, {2, 7}, {3, 8}, {4, 9},
		{5, 7}, {7, 9}, {9, 6}, {6, 8}, {8, 5},
	}
	sCol, _ := bqs.Colouring(10, 3, edges)
	wCol1 := bqs.ColouringWitness([]int{0, 1, 0, 1, 2, 1, 2, 2, 0, 0}, 3)
	wCol2 := bqs.ColouringWitness([]int{2, 0, 2, 0, 1, 0, 1, 1, 2, 2}, 3)

	// 3. 3-SAT gate reduction (Section 4.1, two witnesses of different Hamming weights).
	clauses := [][3]int{
		{1, -4, 3}, {-1, 4, 5}, {6, -1, 3}, {-6, 1, 5},
		{2, -3, -5}, {4, -6, 3}, {-4, 6, 5}, {1, 2, 6},
	}
	sSAT, _ := bqs.ThreeSAT(6, clauses)
	wSAT1 := bqs.ThreeSATWitness([]bool{true, true, false, true, false, true}, clauses)
	wSAT2 := bqs.ThreeSATWitness([]bool{false, true, false, false, false, false}, clauses)

	// 4. Operator-free 2-of-2 Bitcoin Private Signet Taproot Bridge Vault.
	initCtx := bqs.BridgeContext{
		VaultOutPoint:    "pending-signet-utxo:0",
		RecipientAddress: "tb1p-pending-signet-claimer",
		AmountSats:       signet.VaultWithdrawSats,
	}
	s1 := [16]byte{0xca, 0xfe, 0xba, 0xbe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc}
	s3 := [16]byte{0xde, 0xad, 0xbe, 0xef, 0xf0, 0x0d, 0xca, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	var batch [bqs.BridgeBatchSlots]bqs.BridgeNoteCommitment
	batch[0] = bqs.CommitBridgeBurn(initCtx, [16]byte{1})
	batch[1] = bqs.CommitBridgeBurn(initCtx, s1)
	batch[2] = bqs.CommitBridgeBurn(initCtx, [16]byte{2})
	batch[3] = bqs.CommitBridgeBurn(initCtx, s3)
	sBridge, _ := bqs.BridgeBurn(initCtx, batch)
	wBridge1, _ := bqs.BridgeBurnWitness(1, s1)
	wBridge2, _ := bqs.BridgeBurnWitness(3, s3)

	return []Scenario{
		{
			Name:      "Semiprime Factoring",
			Tag:       "R1CS · 64 vars",
			Statement: "18446743979220271189 = p * q  (p, q < 2^32)",
			Message:   "lock to a statement: factors are the key",
			RawSys:    sFact,
			Witness1:  wFact1,
			Wit1Desc:  "p = 4294967291, q = 4294967279",
			Witness2:  wFact2,
			Wit2Desc:  "p = 4294967279, q = 4294967291 (swapped)",
		},
		{
			Name:      "Petersen 3-Colouring",
			Tag:       "Cosets · Fmax=3",
			Statement: "10 vertices, 15 edges, 3 colours (nu=4 cosets)",
			Message:   "any valid 3-colouring unlocks one ciphertext",
			RawSys:    sCol,
			Witness1:  wCol1,
			Wit1Desc:  "colours (0,1,0,1,2, 1,2,2,0,0)",
			Witness2:  wCol2,
			Wit2Desc:  "permuted (2,0,2,0,1, 0,1,1,2,2)",
		},
		{
			Name:      "3-SAT Gate Circuit",
			Tag:       "NP Gates · 14 vars",
			Statement: "6 vars, 8 clauses -> 16 gate equations",
			Message:   "centered sampler handles unequal witness weights",
			RawSys:    sSAT,
			Witness1:  wSAT1,
			Wit1Desc:  "x = (1,1,0,1,0,1) · high weight",
			Witness2:  wSAT2,
			Wit2Desc:  "x = (0,1,0,0,0,0) · low weight",
		},
		{
			Name:       "Signet 2-of-2 Bridge",
			Tag:        "2-of-2 P2TR · 132v",
			Statement:  "L2 burn Q_ctx(s)==C_j unlocks Depositor's 1/2 PSBT",
			Message:    "depositor-1of2-tapscript-psbt",
			RawSys:     sBridge,
			Witness1:   wBridge1,
			Wit1Desc:   "L2 Burn Slot #1 · 128-bit preimage s_A",
			Witness2:   wBridge2,
			Wit2Desc:   "L2 Burn Slot #3 · 128-bit preimage s_B",
			LiveSignet: true,
		},
	}
}

type signetVaultState struct {
	status       signet.ChainStatus
	vault        *signet.LockedVault
	depRug       signet.UnilateralAttempt
	clmEarly     signet.UnilateralAttempt
	settlement   *signet.SweepSettlement
	utxoUnspent  bool
	secret1Hex   string
	secret3Hex   string
	alreadySwept bool
}

type decOutcome struct {
	label          string
	witDesc        string
	witWeight      int
	unchecked      bool
	plaintext      string
	recoveredBytes []byte
	err            error
	rep            praxis.DecReport
	settlement     *signet.SweepSettlement
	utxoStillSafe  bool
	alreadySwept   bool
}

type compareResult struct {
	toyBytes, advBytes int
	toyG1, toyG2       int
	advG1, advG2       int
	toyEnc, toyDec     time.Duration
	advEnc, advDec     time.Duration
	toyBaby, advBaby   int64
	toyTable, advTable int64
}

// Model holds the state of the interactive Praxis TUI.
type Model struct {
	scenarios []Scenario
	cursor    int
	advanced  bool
	width     int
	height    int

	pp       *praxis.Public
	setupDur time.Duration
	ct       *praxis.Ciphertext
	encRep   praxis.EncReport
	hasCT    bool

	sigEnv   *signet.Env
	sigState *signetVaultState

	lastDec *decOutcome
	cmp     *compareResult
	busy    string
	log     []string
}

type setupDoneMsg struct {
	pp  *praxis.Public
	dur time.Duration
	err error
}

type encDoneMsg struct {
	ct  *praxis.Ciphertext
	rep praxis.EncReport
	err error

	sigEnv   *signet.Env
	sigState *signetVaultState
	newPP    *praxis.Public
	setupDur time.Duration
	newSc    *Scenario
}

type decDoneMsg struct {
	out      decOutcome
	sigEnv   *signet.Env
	sigState *signetVaultState
	newPP    *praxis.Public
	newCT    *praxis.Ciphertext
	newRep   *praxis.EncReport
	newSc    *Scenario
}

type cmpDoneMsg struct {
	res compareResult
	err error
}

// New creates a ready-to-render Praxis TUI model.
func New(startAdvanced bool) *Model {
	m := &Model{
		scenarios: buildScenarios(),
		advanced:  startAdvanced,
		width:     118,
		height:    36,
	}
	m.runSetupSync()
	return m
}

func (m *Model) activeParams() praxis.Params {
	if m.advanced {
		return praxis.Advanced
	}
	return praxis.Toy
}

func (m *Model) activeSystem() *bqs.System {
	par := m.activeParams()
	return m.scenarios[m.cursor].RawSys.PadConstraints(par.JRem())
}

func (m *Model) runSetupSync() {
	start := time.Now()
	pp, err := praxis.Setup(m.activeParams(), m.activeSystem())
	if err == nil {
		m.pp = pp
		m.setupDur = time.Since(start)
		m.hasCT = false
		m.ct = nil
		m.lastDec = nil
		m.sigState = nil
	}
}

func (m *Model) pushLog(entry string) {
	m.log = append(m.log, entry)
	if len(m.log) > 4 {
		m.log = m.log[len(m.log)-4:]
	}
}

func (m *Model) Init() tea.Cmd { return nil }

// lockSignetVaultAndEncrypt funds a 2-of-2 tr(NUMS, multi_a(2, Depositor, Claimer))
// UTXO on Signet (keeping BOTH private keys live), verifies neither party can spend
// unilaterally, and Praxis-encrypts Depositor's 1-of-2 partial PSBT.
func lockSignetVaultAndEncrypt(existingEnv *signet.Env, par praxis.Params, baseSc Scenario) (*signet.Env, *signetVaultState, *praxis.Public, time.Duration, *praxis.Ciphertext, praxis.EncReport, Scenario, error) {
	env := existingEnv
	var err error
	if env == nil {
		env, err = signet.ConnectAttachOrStart("", "")
		if err != nil {
			return nil, nil, nil, 0, nil, praxis.EncReport{}, baseSc, err
		}
	}
	vault, err := env.LockTaprootVault()
	if err != nil {
		return env, nil, nil, 0, nil, praxis.EncReport{}, baseSc, err
	}
	depRug, err := env.AttemptUnilateralSpend(vault, "depositor")
	if err != nil {
		return env, nil, nil, 0, nil, praxis.EncReport{}, baseSc, err
	}
	clmEarly, err := env.AttemptUnilateralSpend(vault, "claimer")
	if err != nil {
		return env, nil, nil, 0, nil, praxis.EncReport{}, baseSc, err
	}
	st, err := env.Status()
	if err != nil {
		return env, nil, nil, 0, nil, praxis.EncReport{}, baseSc, err
	}

	ctx := bqs.BridgeContext{
		VaultOutPoint:    vault.OutPoint(),
		RecipientAddress: vault.RecipientAddress,
		AmountSats:       vault.WithdrawSats,
	}
	var secrets [bqs.BridgeBatchSlots][16]byte
	for i := range secrets {
		_, _ = rand.Read(secrets[i][:])
	}
	var batch [bqs.BridgeBatchSlots]bqs.BridgeNoteCommitment
	for i := range batch {
		batch[i] = bqs.CommitBridgeBurn(ctx, secrets[i])
	}
	rawSys, err := bqs.BridgeBurn(ctx, batch)
	if err != nil {
		return env, nil, nil, 0, nil, praxis.EncReport{}, baseSc, err
	}
	w1, _ := bqs.BridgeBurnWitness(1, secrets[1])
	w2, _ := bqs.BridgeBurnWitness(3, secrets[3])

	tSetup := time.Now()
	pp, err := praxis.Setup(par, rawSys.PadConstraints(par.JRem()))
	if err != nil {
		return env, nil, nil, 0, nil, praxis.EncReport{}, baseSc, err
	}
	setupDur := time.Since(tSetup)

	ct, rep, err := praxis.EncDetailed(pp, vault.DepositorPartialPSBT)
	for i := range vault.DepositorPartialPSBT {
		vault.DepositorPartialPSBT[i] = 0
	}
	vault.DepositorPartialPSBT = nil
	if err != nil {
		return env, nil, nil, 0, nil, praxis.EncReport{}, baseSc, err
	}

	s1Hex := hex.EncodeToString(secrets[1][:])
	s3Hex := hex.EncodeToString(secrets[3][:])
	updatedSc := baseSc
	updatedSc.RawSys = rawSys
	updatedSc.Witness1 = w1
	updatedSc.Witness2 = w2
	updatedSc.Wit1Desc = fmt.Sprintf("Slot #1 · secret %s…", s1Hex[:12])
	updatedSc.Wit2Desc = fmt.Sprintf("Slot #3 · secret %s…", s3Hex[:12])
	updatedSc.Statement = fmt.Sprintf("2-of-2 %s…:%d -> %s…", vault.DepositTxID[:10], vault.DepositVout, vault.RecipientAddress[:14])

	sv := &signetVaultState{
		status:      st,
		vault:       vault,
		depRug:      depRug,
		clmEarly:    clmEarly,
		utxoUnspent: true,
		secret1Hex:  s1Hex,
		secret3Hex:  s3Hex,
	}
	return env, sv, pp, setupDur, ct, rep, updatedSc, nil
}

func (m *Model) cmdEncrypt() tea.Cmd {
	sc := m.scenarios[m.cursor]
	par := m.activeParams()
	pp := m.pp
	existingEnv := m.sigEnv
	return func() tea.Msg {
		if sc.LiveSignet {
			env, sv, newPP, setupDur, ct, rep, newSc, err := lockSignetVaultAndEncrypt(existingEnv, par, sc)
			return encDoneMsg{
				ct:       ct,
				rep:      rep,
				err:      err,
				sigEnv:   env,
				sigState: sv,
				newPP:    newPP,
				setupDur: setupDur,
				newSc:    &newSc,
			}
		}
		ct, rep, err := praxis.EncDetailed(pp, []byte(sc.Message))
		return encDoneMsg{ct: ct, rep: rep, err: err}
	}
}

func (m *Model) cmdDecrypt(which int) tea.Cmd {
	sc := m.scenarios[m.cursor]
	par := m.activeParams()
	pp := m.pp
	ct := m.ct
	existingEnv := m.sigEnv
	existingSig := m.sigState

	return func() tea.Msg {
		var autoPP *praxis.Public
		var autoCT *praxis.Ciphertext
		var autoRep *praxis.EncReport
		var autoSc *Scenario
		env := existingEnv
		sig := existingSig

		if ct == nil {
			if sc.LiveSignet {
				var newSc Scenario
				var rep praxis.EncReport
				var err error
				env, sig, pp, _, ct, rep, newSc, err = lockSignetVaultAndEncrypt(env, par, sc)
				if err != nil {
					return decDoneMsg{out: decOutcome{err: err}, sigEnv: env}
				}
				sc = newSc
				autoPP = pp
				autoCT = ct
				autoRep = &rep
				autoSc = &newSc
			} else {
				var rep praxis.EncReport
				var err error
				ct, rep, err = praxis.EncDetailed(pp, []byte(sc.Message))
				if err != nil {
					return decDoneMsg{out: decOutcome{err: err}}
				}
				autoCT = ct
				autoRep = &rep
			}
		}

		var w []bool
		var label, desc string
		var unchecked bool
		switch which {
		case 1:
			w = sc.Witness1
			label = "Witness w1"
			desc = sc.Wit1Desc
		case 2:
			w = sc.Witness2
			label = "Alternate w2"
			desc = sc.Wit2Desc
		case 3:
			w = append([]bool(nil), sc.Witness1...)
			w[1] = !w[1]
			label = "Tampered w* (bit 1 flipped)"
			desc = "DecUnchecked (Fig. 10 without IsWitness guard)"
			unchecked = true
		}
		wt := 0
		for _, b := range w[1:] {
			if b {
				wt++
			}
		}
		var plain []byte
		var rep praxis.DecReport
		var err error
		if unchecked {
			plain, rep, err = praxis.DecUncheckedDetailed(pp, ct, w)
		} else {
			plain, rep, err = praxis.DecDetailed(pp, ct, w)
		}

		out := decOutcome{
			label:          label,
			witDesc:        desc,
			witWeight:      wt,
			unchecked:      unchecked,
			plaintext:      string(plain),
			recoveredBytes: plain,
			err:            err,
			rep:            rep,
		}

		if sc.LiveSignet && env != nil && sig != nil && sig.vault != nil {
			if err != nil {
				if unspent, uerr := env.IsOutPointUnspent(sig.vault.DepositTxID, sig.vault.DepositVout); uerr == nil {
					sig.utxoUnspent = unspent
					out.utxoStillSafe = unspent
				}
			} else {
				unspent, uerr := env.IsOutPointUnspent(sig.vault.DepositTxID, sig.vault.DepositVout)
				if uerr == nil && unspent {
					settle, serr := env.CoSignAndSweep(sig.vault, plain)
					if serr != nil {
						out.err = serr
					} else {
						sig.settlement = settle
						sig.utxoUnspent = false
						if st, stErr := env.Status(); stErr == nil {
							sig.status = st
						}
						out.settlement = settle
						out.plaintext = fmt.Sprintf("1/2 PSBT (%d B) + Claimer sig -> %d-item OP_CHECKSIGADD tx", len(plain), settle.WitnessItems)
					}
				} else {
					_, txid, witItems, ferr := env.CoSignFinalizeOnly(sig.vault, plain)
					if ferr != nil {
						out.err = ferr
					} else {
						out.alreadySwept = true
						out.settlement = sig.settlement
						out.plaintext = fmt.Sprintf("2-of-2 finalized (%d items · txid %s…)", witItems, txid[:16])
					}
				}
			}
		}

		return decDoneMsg{
			out:      out,
			sigEnv:   env,
			sigState: sig,
			newPP:    autoPP,
			newCT:    autoCT,
			newRep:   autoRep,
			newSc:    autoSc,
		}
	}
}

func (m *Model) cmdCompare() tea.Cmd {
	sc := m.scenarios[m.cursor]
	return func() tea.Msg {
		msg := []byte(sc.Message)
		ppToy, err := praxis.Setup(praxis.Toy, sc.RawSys)
		if err != nil {
			return cmpDoneMsg{err: err}
		}
		ctToy, encToy, err := praxis.EncDetailed(ppToy, msg)
		if err != nil {
			return cmpDoneMsg{err: err}
		}
		_, decToy, err := praxis.DecDetailed(ppToy, ctToy, sc.Witness1)
		if err != nil {
			return cmpDoneMsg{err: err}
		}

		sAdv := sc.RawSys.PadConstraints(praxis.Advanced.JRem())
		ppAdv, err := praxis.Setup(praxis.Advanced, sAdv)
		if err != nil {
			return cmpDoneMsg{err: err}
		}
		ctAdv, encAdv, err := praxis.EncDetailed(ppAdv, msg)
		if err != nil {
			return cmpDoneMsg{err: err}
		}
		_, decAdv, err := praxis.DecDetailed(ppAdv, ctAdv, sc.Witness1)
		if err != nil {
			return cmpDoneMsg{err: err}
		}
		return cmpDoneMsg{res: compareResult{
			toyBytes: encToy.Bytes, advBytes: encAdv.Bytes,
			toyG1: encToy.G1, toyG2: encToy.G2,
			advG1: encAdv.G1, advG2: encAdv.G2,
			toyEnc: encToy.EncDur, toyDec: decToy.TotalDur,
			advEnc: encAdv.EncDur, advDec: decAdv.TotalDur,
			toyBaby: decToy.Search.BabySteps, advBaby: decAdv.Search.BabySteps,
			toyTable: decToy.Search.TableBytes, advTable: decAdv.Search.TableBytes,
		}}
	}
}

func (m *Model) cleanup() {
	if m.sigEnv != nil {
		_ = m.sigEnv.Close()
		m.sigEnv = nil
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case setupDoneMsg:
		m.busy = ""
		if msg.err == nil {
			m.pp = msg.pp
			m.setupDur = msg.dur
		}
		return m, nil

	case encDoneMsg:
		m.busy = ""
		if msg.sigEnv != nil {
			m.sigEnv = msg.sigEnv
		}
		if msg.err != nil {
			m.pushLog("encrypt error: " + msg.err.Error())
			return m, nil
		}
		if msg.newSc != nil {
			m.scenarios[m.cursor] = *msg.newSc
		}
		if msg.newPP != nil {
			m.pp = msg.newPP
			m.setupDur = msg.setupDur
		}
		if msg.sigState != nil {
			m.sigState = msg.sigState
		}
		m.ct = msg.ct
		m.encRep = msg.rep
		m.hasCT = true
		m.lastDec = nil
		modeTag := "TOY"
		if m.advanced {
			modeTag = "ADV"
		}
		if msg.sigState != nil && msg.sigState.vault != nil {
			v := msg.sigState.vault
			m.pushLog(fmt.Sprintf("[%s] Funded 2-of-2 P2TR %s… (#%d, both keys LIVE; unilateral spends BLOCKED), sealed 1/2 PSBT",
				modeTag, v.VaultAddress[:12], v.DepositBlock))
		} else {
			m.pushLog(fmt.Sprintf("[%s] Encrypted %s -> %s (%d G1 + %d G2, %v)",
				modeTag, m.scenarios[m.cursor].Name, fmtBytes(msg.rep.Bytes),
				msg.rep.G1, msg.rep.G2, msg.rep.EncDur.Round(time.Millisecond)))
		}
		return m, nil

	case decDoneMsg:
		m.busy = ""
		if msg.sigEnv != nil {
			m.sigEnv = msg.sigEnv
		}
		if msg.newSc != nil {
			m.scenarios[m.cursor] = *msg.newSc
		}
		if msg.newPP != nil {
			m.pp = msg.newPP
		}
		if msg.newCT != nil {
			m.ct = msg.newCT
			m.hasCT = true
		}
		if msg.newRep != nil {
			m.encRep = *msg.newRep
		}
		if msg.sigState != nil {
			m.sigState = msg.sigState
		}
		o := msg.out
		m.lastDec = &o
		if o.err == nil {
			if o.settlement != nil && !o.alreadySwept {
				m.pushLog(fmt.Sprintf("Co-signed 2-of-2 via %s (Depositor offline) -> tx %s… settled @ #%d",
					o.label, o.settlement.SweepTxID[:12], o.settlement.BlockHeight))
			} else {
				m.pushLog(fmt.Sprintf("Decrypted via %s in %v (offset t=%s, %d+%d steps)",
					o.label, o.rep.TotalDur.Round(time.Millisecond),
					fmtSigned(o.rep.Search.Offset), o.rep.Search.BabySteps, o.rep.Search.GiantSteps))
			}
		} else {
			if o.utxoStillSafe {
				m.pushLog(fmt.Sprintf("Rejected %s -> 2-of-2 Signet UTXO verified UNSPENT (1.0 sBTC safe)", o.label))
			} else {
				m.pushLog(fmt.Sprintf("Rejected %s (%v)", o.label, o.err))
			}
		}
		return m, nil

	case cmpDoneMsg:
		m.busy = ""
		if msg.err == nil {
			res := msg.res
			m.cmp = &res
			m.pushLog(fmt.Sprintf("Benchmarked Toy vs Advanced: search table %s -> %s",
				fmtBytes(int(res.toyTable)), fmtBytes(int(res.advTable))))
		}
		return m, nil

	case tea.KeyPressMsg:
		if m.busy != "" && msg.String() != "ctrl+c" && msg.String() != "q" {
			return m, nil
		}
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			m.cleanup()
			return m, tea.Quit
		case "m", "tab":
			m.advanced = !m.advanced
			m.cmp = nil
			m.runSetupSync()
			if m.advanced {
				m.pushLog("Switched to ADVANCED mode (n=24, J=4/J'=2, FFT QAP, outward sign-FP64)")
			} else {
				m.pushLog("Switched to TOY mode (n=8, J=1/J'=1, schoolbook QAP, interval BSGS)")
			}
		case "up", "k":
			m.cursor = (m.cursor - 1 + len(m.scenarios)) % len(m.scenarios)
			m.cmp = nil
			m.runSetupSync()
		case "down", "j":
			m.cursor = (m.cursor + 1) % len(m.scenarios)
			m.cmp = nil
			m.runSetupSync()
		case "1", "2", "3", "4":
			idx := int(msg.String()[0] - '1')
			if idx >= 0 && idx < len(m.scenarios) {
				m.cursor = idx
				m.cmp = nil
				m.runSetupSync()
			}
		case "e", "enter":
			if m.scenarios[m.cursor].LiveSignet {
				m.busy = "Funding 2-of-2 P2TR vault, checking unilateral blocks & sealing 1/2 PSBT..."
			} else {
				m.busy = "Encrypting statement (Fig. 9)..."
			}
			m.cmp = nil
			return m, m.cmdEncrypt()
		case "d":
			if m.scenarios[m.cursor].LiveSignet {
				m.busy = "Proving L2 burn w1 -> decrypt 1/2 PSBT -> Claimer co-sign & mine..."
			} else {
				m.busy = "Decrypting with witness w1 (Fig. 10)..."
			}
			m.cmp = nil
			return m, m.cmdDecrypt(1)
		case "w":
			if m.scenarios[m.cursor].LiveSignet {
				m.busy = "Proving alternate L2 burn w2 -> decrypt 1/2 PSBT & co-sign..."
			} else {
				m.busy = "Decrypting same ciphertext with alternate witness w2..."
			}
			m.cmp = nil
			return m, m.cmdDecrypt(2)
		case "x":
			if m.scenarios[m.cursor].LiveSignet {
				m.busy = "Attacking vault with forged burn proof (DecUnchecked)..."
			} else {
				m.busy = "Running DecUnchecked on tampered witness..."
			}
			m.cmp = nil
			return m, m.cmdDecrypt(3)
		case "c":
			m.busy = "Comparing Toy vs Advanced modes..."
			return m, m.cmdCompare()
		}
	}
	return m, nil
}

func sectionBar(title, right string, width int) string {
	left := stPurple.Render("▸ ") + stTitle.Render(title)
	r := ""
	if right != "" {
		r = " " + stMuted.Render(right)
	}
	used := ansi.StringWidth(left) + ansi.StringWidth(r) + 1
	fill := max(2, width-used)
	return left + " " + stRule.Render(strings.Repeat("─", fill)) + r
}

func padOrTrim(s string, width int) string {
	w := ansi.StringWidth(s)
	if w > width {
		return ansi.Truncate(s, width, "…")
	}
	return s + strings.Repeat(" ", width-w)
}

func cardBox(lines []string, innerW int, focused bool) string {
	edgeCol := colRule
	if focused {
		edgeCol = colPurple
	}
	leftEdge := lipgloss.NewStyle().Foreground(edgeCol).Background(colPane).Render("▏")
	rightEdge := lipgloss.NewStyle().Foreground(edgeCol).Background(colPane).Render("▕")
	bodyBg := lipgloss.NewStyle().Background(colPane)
	var out []string
	for _, ln := range lines {
		padded := " " + padOrTrim(ln, innerW-4) + " "
		out = append(out, leftEdge+bodyBg.Render(padded)+rightEdge)
	}
	return strings.Join(out, "\n")
}

func fmtBytes(b int) string {
	if b >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024.0)
	}
	return fmt.Sprintf("%d B", b)
}

func fmtSigned(x *big.Int) string {
	if x == nil {
		return "—"
	}
	if x.Sign() >= 0 {
		return "+" + x.String()
	}
	return x.String()
}

func (m *Model) View() tea.View {
	w := m.width
	if w < 88 {
		w = 88
	}
	if w > 146 {
		w = 146
	}
	inner := w - 2

	// Header banner
	mark := stPurple.Render("π") + " " + stTitle.Render("PRAXIS") + " " + stSub.Render("Witness Encryption Workbench · ePrint 2026/2971")
	modePill := stPillToy.Render("TOY MODE · Baseline")
	if m.advanced {
		modePill = stPillAdv.Render("ADVANCED MODE · Full Spec (Sec. 4.4 & 5.2)")
	}
	warnPill := stPillWarn.Render("DEMO · NOT CONSTANT-TIME")
	rightHead := modePill + " " + warnPill
	gap := max(2, inner-ansi.StringWidth(mark)-ansi.StringWidth(rightHead))
	header := " " + mark + strings.Repeat(" ", gap) + rightHead

	leftW := min(52, inner*42/100)
	rightW := inner - leftW - 2

	// --- LEFT COLUMN ---
	var leftLines []string
	leftLines = append(leftLines, sectionBar("NP STATEMENTS", "1-4 / ↑↓", leftW-4))
	for i, sc := range m.scenarios {
		prefix := "  "
		nameRendered := stSub.Render(sc.Name)
		if i == m.cursor {
			prefix = stPurple.Render("▸ ")
			nameRendered = stCyan.Render(sc.Name)
		}
		tag := stMuted.Render(sc.Tag)
		padN := max(1, (leftW-4)-ansi.StringWidth(prefix)-ansi.StringWidth(nameRendered)-ansi.StringWidth(tag))
		leftLines = append(leftLines, prefix+nameRendered+strings.Repeat(" ", padN)+tag)
	}
	sc := m.scenarios[m.cursor]
	leftLines = append(leftLines, "")
	leftLines = append(leftLines, stMuted.Render("Statement:")+" "+stInk(sc.Statement))
	leftLines = append(leftLines, stMuted.Render("w1:")+" "+stSub.Render(sc.Wit1Desc))
	leftLines = append(leftLines, stMuted.Render("w2:")+" "+stSub.Render(sc.Wit2Desc))

	leftLines = append(leftLines, "")
	par := m.activeParams()
	modeName := "TOY"
	qapAlg := "Schoolbook O(D^2) · coset powers"
	extDesc := fmt.Sprintf("F_q[T]/(T^%d - c0) · pow-of-2", par.NForms())
	searchAlg := "Growing-interval BSGS (392 B/step)"
	if m.advanced {
		modeName = "ADVANCED"
		qapAlg = "Radix-2 FFT O(|H| log |H|) · bit-rev H"
		extDesc = fmt.Sprintf("F_q[T]/(T^%d - c0) · Serret 2,3|n", par.NForms())
		searchAlg = "Outward {V,V^-1} sign-FP64 (12 B/step)"
	}
	leftLines = append(leftLines, sectionBar("ACTIVE ENGINE · "+modeName, "tab", leftW-4))
	leftLines = append(leftLines, kvRow("Ring / Grid", fmt.Sprintf("dR=%d, K=%d -> %d forms, %dx%d=%d cells",
		par.DR, par.K, par.NForms(), par.K1, 3*par.K2, par.Cells()), leftW-4))
	leftLines = append(leftLines, kvRow("Extension", extDesc, leftW-4))
	leftLines = append(leftLines, kvRow("Power Chunks", fmt.Sprintf("J=%d quo, J'=%d rem", par.JQuo(), par.JRem()), leftW-4))
	leftLines = append(leftLines, kvRow("QAP Engine", qapAlg, leftW-4))
	leftLines = append(leftLines, kvRow("Secret Range", fmt.Sprintf("g = 2^%d (%d)", int(math.Log2(float64(par.G))), par.G), leftW-4))
	leftLines = append(leftLines, kvRow("DL Search", searchAlg, leftW-4))

	// --- RIGHT COLUMN ---
	var rightLines []string
	pp := m.pp
	g1Count, g2Count := pp.Counts()
	c0 := pp.C0()
	c0Int := c0.BigInt(new(big.Int))
	rightLines = append(rightLines, sectionBar("QAP & CHUNK GEOMETRY", fmt.Sprintf("Setup %v", m.setupDur.Round(100*time.Microsecond)), rightW-4))
	rightLines = append(rightLines, fmt.Sprintf("%s %s   %s %s   %s %s   %s %s",
		stMuted.Render("N="), stCoral.Render(fmt.Sprintf("%d", pp.S.N)),
		stMuted.Render("nc="), stCoral.Render(fmt.Sprintf("%d", len(pp.S.Constraints))),
		stMuted.Render("nu="), stCoral.Render(fmt.Sprintf("%d", pp.Nu)),
		stMuted.Render("|H|="), stCoral.Render(fmt.Sprintf("%d (D=%d)", pp.SubgroupSize, pp.D)),
	))
	rightLines = append(rightLines, fmt.Sprintf("%s %s   %s %s   %s %s",
		stMuted.Render("c0="), stYellow.Render(c0Int.String()),
		stMuted.Render("Quo(J,Δ)="), stCyan.Render(fmt.Sprintf("(%d, %d)", par.JQuo(), pp.Delta)),
		stMuted.Render("Rem(J',Δ')="), stCyan.Render(fmt.Sprintf("(%d, %d)", par.JRem(), pp.DeltaPrime)),
	))
	rightLines = append(rightLines, fmt.Sprintf("%s %s G1 + %s G2 (incl. α) + 1 GT",
		stMuted.Render("Prop 5.7 Counts:"),
		stGreen.Render(fmt.Sprintf("%d", g1Count)),
		stPurple.Render(fmt.Sprintf("%d", g2Count)),
	))

	if sc.LiveSignet {
		rightLines = append(rightLines, "")
		rightLines = append(rightLines, sectionBar("BITCOIN PRIVATE SIGNET · 2-OF-2 P2TR VAULT", "challenge=51", rightW-4))
		if m.sigState == nil || m.sigState.vault == nil {
			rightLines = append(rightLines, stMuted.Render("Script: ")+stCyan.Render("tr(NUMS, multi_a(2, Depositor, Claimer))")+stMuted.Render(" · OP_CHECKSIGADD"))
			rightLines = append(rightLines, stMuted.Render("Press ")+stCyan.Render("[e]")+stMuted.Render(" to fund 1.0 sBTC (both keys kept LIVE; Depositor seals 1/2 PSBT)."))
		} else {
			sv := m.sigState
			v := sv.vault
			peerBadge := ""
			if sv.status.PeerHeight >= 0 {
				peerBadge = fmt.Sprintf(" · peer :38402 #%d", sv.status.PeerHeight)
			}
			utxoBadge := stYellow.Render("UNSPENT (1.0 sBTC)")
			if !sv.utxoUnspent {
				utxoBadge = stGreen.Render("CO-SIGNED & SWEPT")
			}
			rightLines = append(rightLines, fmt.Sprintf("%s %s (%s #%d%s) · %s",
				stMuted.Render("Network:"), stCyan.Render(sv.status.Mode), sv.status.PrimaryRPC, sv.status.Height, peerBadge, utxoBadge))
			rightLines = append(rightLines, fmt.Sprintf("%s %s · %s · %s",
				stMuted.Render("2-of-2:"),
				stSub.Render("BOTH KEYS LIVE"),
				stGreen.Render(fmt.Sprintf("Dep rug-pull=%v", sv.depRug.FinalizableAlone)),
				stGreen.Render(fmt.Sprintf("Clm alone=%v", sv.clmEarly.FinalizableAlone)),
			))
			rightLines = append(rightLines, fmt.Sprintf("%s %s:%d (#%d) -> %s…",
				stMuted.Render("Deposit:"), stSub.Render(v.DepositTxID[:14]+"…"), v.DepositVout, v.DepositBlock, v.RecipientAddress[:18]))
			if sv.settlement != nil {
				s := sv.settlement
				rightLines = append(rightLines, fmt.Sprintf("%s %s · #%d · %d witness items · %.5f sBTC",
					stGreen.Render("✓ Sweep:"), stTitle.Render(s.SweepTxID[:16]+"…"), s.BlockHeight, s.WitnessItems, float64(s.RecipientSats)/1e8))
			}
		}
	}

	rightLines = append(rightLines, "")
	if m.cmp != nil {
		c := m.cmp
		colRow := func(c1, c2, c3 string) string {
			return "  " + padOrTrim(c1, 16) + "  " + padOrTrim(c2, 27) + "  " + padOrTrim(c3, 29)
		}
		rightLines = append(rightLines, sectionBar("TOY vs ADVANCED BENCHMARK", "live run", rightW-4))
		rightLines = append(rightLines, colRow(
			stMuted.Render("Metric"),
			stCyan.Render("TOY (n=8, J=1, g=2^20)"),
			stPurple.Render("ADVANCED (n=24, J=4/2, g=2^24)"),
		))
		rightLines = append(rightLines, colRow(
			stMuted.Render("Ciphertext"),
			stSub.Render(fmt.Sprintf("%s (%d+%d)", fmtBytes(c.toyBytes), c.toyG1, c.toyG2)),
			stSub.Render(fmt.Sprintf("%s (%d+%d)", fmtBytes(c.advBytes), c.advG1, c.advG2)),
		))
		rightLines = append(rightLines, colRow(
			stMuted.Render("Enc / Dec"),
			stSub.Render(fmt.Sprintf("%v / %v", c.toyEnc.Round(time.Millisecond), c.toyDec.Round(time.Millisecond))),
			stSub.Render(fmt.Sprintf("%v / %v", c.advEnc.Round(time.Millisecond), c.advDec.Round(time.Millisecond))),
		))
		rightLines = append(rightLines, colRow(
			stMuted.Render("Baby Table"),
			stSub.Render(fmt.Sprintf("%d steps (%s)", c.toyBaby, fmtBytes(int(c.toyTable)))),
			stGreen.Render(fmt.Sprintf("%d steps (%s · FP64)", c.advBaby, fmtBytes(int(c.advTable)))),
		))
	} else {
		rightLines = append(rightLines, sectionBar("CRYPTOGRAPHIC PIPELINE", "Fig. 9 & 10", rightW-4))
		if !m.hasCT {
			rightLines = append(rightLines, stMuted.Render("Press ")+stCyan.Render("[e]")+stMuted.Render(" to encrypt statement, or ")+
				stCyan.Render("[d]")+stMuted.Render(" / ")+stCyan.Render("[w]")+stMuted.Render(" / ")+stCyan.Render("[x]")+stMuted.Render(" to run end-to-end."))
		} else {
			rightLines = append(rightLines, stGreen.Render("✓ Ciphertext Sealed")+" · "+
				stCoral.Render(fmtBytes(m.encRep.Bytes))+" in "+stYellow.Render(m.encRep.EncDur.Round(time.Millisecond).String())+
				stMuted.Render(" · no secret key retained"))
		}

		if m.lastDec != nil {
			o := m.lastDec
			s := o.rep.Search
			rightLines = append(rightLines, "")
			qapBadge := stGreen.Render("EXACT (rem allowed)")
			if !o.rep.ExactQAP {
				qapBadge = stRed.Render("NON-ZERO REMAINDER")
			}
			rightLines = append(rightLines, fmt.Sprintf("%s %s · wt(w)=%d · QAP: %s",
				stTitle.Render(o.label+":"), stSub.Render(o.witDesc), o.witWeight, qapBadge))
			rightLines = append(rightLines, fmt.Sprintf("%s forms %v · QAP %v · %d pairings %v · search %v",
				stMuted.Render("Timings:"),
				o.rep.FormsDur.Round(100*time.Microsecond),
				o.rep.QAPDur.Round(100*time.Microsecond),
				o.rep.Pairings,
				o.rep.PairingsDur.Round(time.Millisecond),
				o.rep.SearchDur.Round(100*time.Microsecond),
			))
			centerStr := "—"
			if s.Center != nil {
				centerStr = s.Center.String()
			}
			fpNote := ""
			if s.Algorithm == "outward-sign-fp64" {
				fpNote = fmt.Sprintf(" · FP64 hits=%d (false=%d)", s.FingerprintHits, s.FalsePositives)
			}
			rightLines = append(rightLines, fmt.Sprintf("%s c_w=%s · t=%s · baby=%d (%s) · giant=%d%s",
				stMuted.Render("Search:"),
				centerStr,
				stYellow.Render(fmtSigned(s.Offset)),
				s.BabySteps, fmtBytes(int(s.TableBytes)),
				s.GiantSteps, fpNote,
			))
			rightLines = append(rightLines, renderSearchBar(s.Offset, pp.S.N, par.G, rightW-4))
			if o.err == nil {
				if o.settlement != nil && !o.alreadySwept {
					rightLines = append(rightLines, stGreen.Render("🔓 SWEPT ON SIGNET: ")+
						stTitle.Render(fmt.Sprintf("tx %s… confirmed @ #%d", o.settlement.SweepTxID[:18], o.settlement.BlockHeight)))
				} else {
					rightLines = append(rightLines, stGreen.Render("🔓 UNLOCKED: ")+stTitle.Render(fmt.Sprintf("%q", o.plaintext)))
				}
			} else {
				extra := ""
				if o.utxoStillSafe {
					extra = " · 2-of-2 UTXO still UNSPENT on Signet"
				}
				rightLines = append(rightLines, stRed.Render("✗ REJECTED: ")+stSub.Render(o.err.Error()+extra))
			}
		}
	}

	targetH := max(len(leftLines), len(rightLines))
	for len(leftLines) < targetH {
		leftLines = append(leftLines, "")
	}
	for len(rightLines) < targetH {
		rightLines = append(rightLines, "")
	}

	leftCard := cardBox(leftLines, leftW, true)
	rightCard := cardBox(rightLines, rightW, m.hasCT)
	columns := lipgloss.JoinHorizontal(lipgloss.Top, leftCard, "  ", rightCard)

	var logLines []string
	logLines = append(logLines, sectionBar("EVENT TRACE", m.busy, inner-4))
	if len(m.log) == 0 {
		logLines = append(logLines, stMuted.Render("Ready. Press [4] for 2-of-2 Bitcoin Signet Vault, [tab] Toy/Adv, [e] Lock/Encrypt, [d] Co-sign/Sweep, [x] Forged Proof."))
	} else {
		for _, entry := range m.log {
			logLines = append(logLines, stSub.Render("· ")+stInk(entry))
		}
	}
	logBox := cardBox(logLines, inner, false)

	keys := []string{
		stPurple.Render("1-4/↑↓") + " " + stMuted.Render("statement"),
		stPurple.Render("tab") + " " + stMuted.Render("toy/advanced"),
		stCyan.Render("e") + " " + stMuted.Render("lock/encrypt"),
		stGreen.Render("d") + " " + stMuted.Render("prove w1"),
		stGreen.Render("w") + " " + stMuted.Render("alt w2"),
		stRed.Render("x") + " " + stMuted.Render("tamper"),
		stYellow.Render("c") + " " + stMuted.Render("compare"),
		stMuted.Render("q quit"),
	}
	footer := " " + strings.Join(keys, stRule.Render(" · "))

	var out strings.Builder
	out.WriteString("\n")
	out.WriteString(header + "\n\n")
	for _, row := range strings.Split(columns, "\n") {
		out.WriteString(" " + row + "\n")
	}
	out.WriteString("\n")
	for _, row := range strings.Split(logBox, "\n") {
		out.WriteString(" " + row + "\n")
	}
	out.WriteString("\n" + footer + "\n")

	v := tea.NewView(out.String())
	v.AltScreen = true
	return v
}

func stInk(s string) string {
	return lipgloss.NewStyle().Foreground(colInk).Render(s)
}

func kvRow(k, v string, width int) string {
	keyPart := stMuted.Render(fmt.Sprintf("%-12s ", k))
	rem := max(8, width-ansi.StringWidth(keyPart))
	return keyPart + stSub.Render(ansi.Truncate(v, rem, "…"))
}

func renderSearchBar(offset *big.Int, N int, g int64, width int) string {
	barW := max(24, width-18)
	mid := barW / 2
	sigma := float64(g)*math.Sqrt(float64(N+4)/48.0) + 1.0
	span := 3.0 * sigma
	pos := -1
	if offset != nil {
		f, _ := new(big.Float).SetInt(offset).Float64()
		norm := (f / span) * float64(mid)
		pos = mid + int(math.Round(norm))
		pos = max(0, min(barW-1, pos))
	}
	var b strings.Builder
	b.WriteString(stMuted.Render("Offset [-3σ,+3σ] "))
	b.WriteString(stRule.Render("["))
	for i := 0; i < barW; i++ {
		switch {
		case i == pos:
			b.WriteString(stGreen.Render("●"))
		case i == mid:
			b.WriteString(stCyan.Render("│"))
		default:
			b.WriteString(stRule.Render("─"))
		}
	}
	b.WriteString(stRule.Render("]"))
	return b.String()
}

// Run launches the interactive Praxis TUI in the terminal.
func Run(startAdvanced bool) error {
	m := New(startAdvanced)
	defer m.cleanup()
	_, err := tea.NewProgram(m).Run()
	return err
}
