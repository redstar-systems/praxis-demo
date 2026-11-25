// Package tui implements a SilkCircuit-styled Charm v2 workbench for exploring
// Praxis witness encryption across the 6-tier parameter spectrum (from Toy
// n=8, g=2^20 up to Paper Table 4's n=4608, g~2^50.6), Theorem 5.9 (P1)/MSIS
// admissibility padding, and the live 2-of-2 Bitcoin Private Signet vault.
package tui

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"image/color"
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

// silkPalette holds one SilkCircuit variant's published colors (matching crust/styles/silkcircuit.go).
type silkPalette struct {
	name      string
	bg        color.Color
	pane      color.Color
	highlight color.Color
	chrome    color.Color
	rule      color.Color
	ink       color.Color
	sub       color.Color
	muted     color.Color
	purple    color.Color
	pink      color.Color
	cyan      color.Color
	green     color.Color
	coral     color.Color
	red       color.Color
	yellow    color.Color
}

var palettes = []silkPalette{
	{
		name:      "neon",
		bg:        lipgloss.Color("#12101a"),
		pane:      lipgloss.Color("#0a0812"),
		highlight: lipgloss.Color("#1a162a"),
		chrome:    lipgloss.Color("#221e32"),
		rule:      lipgloss.Color("#39305c"),
		ink:       lipgloss.Color("#f8f8f2"),
		sub:       lipgloss.Color("#e9d5ff"),
		muted:     lipgloss.Color("#768d8d"),
		purple:    lipgloss.Color("#e135ff"),
		pink:      lipgloss.Color("#ff69ff"),
		cyan:      lipgloss.Color("#80ffea"),
		green:     lipgloss.Color("#50fa7b"),
		coral:     lipgloss.Color("#ff6ac1"),
		red:       lipgloss.Color("#ff6363"),
		yellow:    lipgloss.Color("#f1fa8c"),
	},
	{
		name:      "vibrant",
		bg:        lipgloss.Color("#0f0c1a"),
		pane:      lipgloss.Color("#08060f"),
		highlight: lipgloss.Color("#151026"),
		chrome:    lipgloss.Color("#1e1834"),
		rule:      lipgloss.Color("#3b2d6a"),
		ink:       lipgloss.Color("#f8f8f2"),
		sub:       lipgloss.Color("#e9d5ff"),
		muted:     lipgloss.Color("#728989"),
		purple:    lipgloss.Color("#ff00ff"),
		pink:      lipgloss.Color("#ff66ff"),
		cyan:      lipgloss.Color("#00ffcc"),
		green:     lipgloss.Color("#00ff66"),
		coral:     lipgloss.Color("#ff5fa8"),
		red:       lipgloss.Color("#ff3366"),
		yellow:    lipgloss.Color("#ffcc00"),
	},
	{
		name:      "soft",
		bg:        lipgloss.Color("#1a1626"),
		pane:      lipgloss.Color("#141220"),
		highlight: lipgloss.Color("#201b30"),
		chrome:    lipgloss.Color("#2b253d"),
		rule:      lipgloss.Color("#403660"),
		ink:       lipgloss.Color("#f8f8f2"),
		sub:       lipgloss.Color("#e9d5ff"),
		muted:     lipgloss.Color("#7e9494"),
		purple:    lipgloss.Color("#e892ff"),
		pink:      lipgloss.Color("#ffb3ff"),
		cyan:      lipgloss.Color("#99ffee"),
		green:     lipgloss.Color("#66ff99"),
		coral:     lipgloss.Color("#ff99dd"),
		red:       lipgloss.Color("#ff6677"),
		yellow:    lipgloss.Color("#ffe699"),
	},
	{
		name:      "glow",
		bg:        lipgloss.Color("#0a0816"),
		pane:      lipgloss.Color("#05030c"),
		highlight: lipgloss.Color("#1a0033"),
		chrome:    lipgloss.Color("#250047"),
		rule:      lipgloss.Color("#49008f"),
		ink:       lipgloss.Color("#ffffff"),
		sub:       lipgloss.Color("#cc66ff"),
		muted:     lipgloss.Color("#818181"),
		purple:    lipgloss.Color("#dd00ff"),
		pink:      lipgloss.Color("#ff55ff"),
		cyan:      lipgloss.Color("#00ffff"),
		green:     lipgloss.Color("#50fa7b"),
		coral:     lipgloss.Color("#ff6ac1"),
		red:       lipgloss.Color("#ff5555"),
		yellow:    lipgloss.Color("#f1fa8c"),
	},
}

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
	csvEarly     signet.CSVRefundAttempt
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

type sweepRow struct {
	tier       praxis.Tier
	bytes      int
	g1, g2     int
	encDur     time.Duration
	decDur     time.Duration
	searchDur  time.Duration
	babySteps  int64
	tableBytes int64
}

type compareResult struct {
	rows     []sweepRow
	toyTable int64
	advTable int64
}

// Model holds the state of the interactive Praxis TUI.
type Model struct {
	scenarios     []Scenario
	cursor        int
	tierIdx       int  // 0..5 into praxis.Spectrum
	advanced      bool // true when tierIdx >= 1 (preserved for tests)
	padAdmissible bool // [p] pad unknowns N >= n so Theorem 5.9 (P1) and ell > K hold
	palIdx        int  // SilkCircuit variant index
	width         int
	height        int

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

// New creates a ready-to-render Praxis TUI model (Tier 2 Advanced if startAdvanced, else Tier 1 Toy).
func New(startAdvanced bool) *Model {
	tIdx := 0
	if startAdvanced {
		tIdx = 1
	}
	return NewAtTier(tIdx + 1)
}

// NewAtTier creates a Praxis TUI model initialized at tier 1..6.
func NewAtTier(tier1Based int) *Model {
	if tier1Based < 1 {
		tier1Based = 1
	}
	if tier1Based > len(praxis.Spectrum) {
		tier1Based = len(praxis.Spectrum)
	}
	m := &Model{
		scenarios: buildScenarios(),
		tierIdx:   tier1Based - 1,
		advanced:  tier1Based > 1,
		width:     124,
		height:    38,
	}
	m.runSetupSync()
	return m
}

func (m *Model) activeTier() praxis.Tier {
	return praxis.Spectrum[m.tierIdx]
}

func (m *Model) activeParams() praxis.Params {
	return m.activeTier().Params
}

func (m *Model) activeSystemFor(raw *bqs.System, par praxis.Params) *bqs.System {
	sys := raw
	if m.padAdmissible {
		sys = sys.PadUnknowns(par.NForms())
	}
	return sys.PadConstraints(par.JRem())
}

func (m *Model) activeSystem() *bqs.System {
	return m.activeSystemFor(m.scenarios[m.cursor].RawSys, m.activeParams())
}

func (m *Model) setTierIndex(idx int) {
	if idx < 0 {
		idx = 0
	}
	if idx >= len(praxis.Spectrum) {
		idx = len(praxis.Spectrum) - 1
	}
	m.tierIdx = idx
	m.advanced = idx > 0
	m.cmp = nil
	m.runSetupSync()
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

func lockSignetVaultAndEncrypt(existingEnv *signet.Env, par praxis.Params, padAdm bool, baseSc Scenario) (*signet.Env, *signetVaultState, *praxis.Public, time.Duration, *praxis.Ciphertext, praxis.EncReport, Scenario, error) {
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
	csvEarly, err := env.AttemptPrematureCSVRefund(vault)
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

	sys := rawSys
	if padAdm {
		sys = sys.PadUnknowns(par.NForms())
	}
	sys = sys.PadConstraints(par.JRem())

	tSetup := time.Now()
	pp, err := praxis.Setup(par, sys)
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
		csvEarly:    csvEarly,
		utxoUnspent: true,
		secret1Hex:  s1Hex,
		secret3Hex:  s3Hex,
	}
	return env, sv, pp, setupDur, ct, rep, updatedSc, nil
}

func (m *Model) cmdEncrypt() tea.Cmd {
	sc := m.scenarios[m.cursor]
	par := m.activeParams()
	padAdm := m.padAdmissible
	pp := m.pp
	existingEnv := m.sigEnv
	return func() tea.Msg {
		if sc.LiveSignet {
			env, sv, newPP, setupDur, ct, rep, newSc, err := lockSignetVaultAndEncrypt(existingEnv, par, padAdm, sc)
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
	padAdm := m.padAdmissible
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
				env, sig, pp, _, ct, rep, newSc, err = lockSignetVaultAndEncrypt(env, par, padAdm, sc)
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
			w = bqs.PadWitness(sc.Witness1, pp.S.N)
			label = "Witness w1"
			desc = sc.Wit1Desc
		case 2:
			w = bqs.PadWitness(sc.Witness2, pp.S.N)
			label = "Alternate w2"
			desc = sc.Wit2Desc
		case 3:
			w = append([]bool(nil), bqs.PadWitness(sc.Witness1, pp.S.N)...)
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
	// Sweep Tiers 1..4 interactively (~1.2s total across 4 orders of magnitude in g!).
	return func() tea.Msg {
		msg := []byte(sc.Message)
		var rows []sweepRow
		for idx := 0; idx < 4; idx++ {
			tier := praxis.Spectrum[idx]
			sys := sc.RawSys.PadConstraints(tier.Params.JRem())
			pp, err := praxis.Setup(tier.Params, sys)
			if err != nil {
				return cmpDoneMsg{err: err}
			}
			ct, encRep, err := praxis.EncDetailed(pp, msg)
			if err != nil {
				return cmpDoneMsg{err: err}
			}
			w := bqs.PadWitness(sc.Witness1, pp.S.N)
			_, decRep, err := praxis.DecDetailed(pp, ct, w)
			if err != nil {
				return cmpDoneMsg{err: err}
			}
			rows = append(rows, sweepRow{
				tier:       tier,
				bytes:      encRep.Bytes,
				g1:         encRep.G1,
				g2:         encRep.G2,
				encDur:     encRep.EncDur,
				decDur:     decRep.TotalDur,
				searchDur:  decRep.SearchDur,
				babySteps:  decRep.Search.BabySteps,
				tableBytes: decRep.Search.TableBytes,
			})
		}
		return cmpDoneMsg{res: compareResult{
			rows:     rows,
			toyTable: rows[0].tableBytes,
			advTable: rows[1].tableBytes,
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
		tier := m.activeTier()
		if msg.sigState != nil && msg.sigState.vault != nil {
			v := msg.sigState.vault
			m.pushLog(fmt.Sprintf("[T%d:%s] Funded 2-of-2 P2TR %s… (#%d, both keys LIVE), sealed %s CT",
				tier.Index, tier.Name, v.VaultAddress[:12], v.DepositBlock, fmtBytes(msg.rep.Bytes)))
		} else {
			m.pushLog(fmt.Sprintf("[T%d:%s] Encrypted %s -> %s (%d G1 + %d G2, %v)",
				tier.Index, tier.Name, m.scenarios[m.cursor].Name, fmtBytes(msg.rep.Bytes),
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
				m.pushLog(fmt.Sprintf("[T%d] Decrypted via %s in %v (search %v, %d+%d steps)",
					m.activeTier().Index, o.label, o.rep.TotalDur.Round(time.Millisecond),
					o.rep.SearchDur.Round(time.Millisecond), o.rep.Search.BabySteps, o.rep.Search.GiantSteps))
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
			m.pushLog(fmt.Sprintf("Swept Tiers 1..4 (n=8 -> 384, g=2^20 -> 2^40): Tier 4 Dec in %v",
				res.rows[len(res.rows)-1].decDur.Round(time.Millisecond)))
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
			if m.tierIdx == 0 {
				m.setTierIndex(1)
			} else {
				m.setTierIndex(0)
			}
			t := m.activeTier()
			m.pushLog(fmt.Sprintf("Toggled to Tier %d (%s: n=%d, g=2^%.1f)",
				t.Index, t.Name, t.Params.NForms(), math.Log2(float64(t.Params.G))))
		case "[", "left", "h", "-":
			if m.tierIdx > 0 {
				m.setTierIndex(m.tierIdx - 1)
				t := m.activeTier()
				m.pushLog(fmt.Sprintf("Stepped down spectrum -> Tier %d (%s: n=%d, %d cells, g=2^%.1f)",
					t.Index, t.Name, t.Params.NForms(), t.Params.Cells(), math.Log2(float64(t.Params.G))))
			}
		case "]", "right", "l", "+", "=":
			if m.tierIdx+1 < len(praxis.Spectrum) {
				m.setTierIndex(m.tierIdx + 1)
				t := m.activeTier()
				m.pushLog(fmt.Sprintf("Stepped up spectrum -> Tier %d (%s: n=%d, %d cells, g=2^%.1f)",
					t.Index, t.Name, t.Params.NForms(), t.Params.Cells(), math.Log2(float64(t.Params.G))))
			}
		case "p":
			m.padAdmissible = !m.padAdmissible
			m.cmp = nil
			m.runSetupSync()
			adm := m.pp.Admissibility()
			if m.padAdmissible {
				m.pushLog(fmt.Sprintf("Enabled (P1)/MSIS padding: N=%d -> D=%d >= n=%d, ell=%d > K=%d",
					adm.N, adm.D, adm.NForms, adm.Ell, adm.K))
			} else {
				m.pushLog(fmt.Sprintf("Disabled (P1)/MSIS padding: restored native circuit N=%d", adm.N))
			}
		case "v":
			m.palIdx = (m.palIdx + 1) % len(palettes)
			m.pushLog("Switched SilkCircuit palette variant -> silkcircuit-" + palettes[m.palIdx].name)
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
			t := m.activeTier()
			if m.scenarios[m.cursor].LiveSignet {
				m.busy = fmt.Sprintf("[T%d:%s] Funding 2-of-2 P2TR vault & sealing 1/2 PSBT...", t.Index, t.Name)
			} else {
				m.busy = fmt.Sprintf("[T%d:%s] Encrypting statement (n=%d, %d cells)...", t.Index, t.Name, t.Params.NForms(), t.Params.Cells())
			}
			m.cmp = nil
			return m, m.cmdEncrypt()
		case "d":
			t := m.activeTier()
			if m.scenarios[m.cursor].LiveSignet {
				m.busy = fmt.Sprintf("[T%d:%s] Proving L2 burn w1 -> decrypt -> Claimer co-sign & mine...", t.Index, t.Name)
			} else {
				m.busy = fmt.Sprintf("[T%d:%s] Decrypting w1 (6-mul F_p Chebyshev search)...", t.Index, t.Name)
			}
			m.cmp = nil
			return m, m.cmdDecrypt(1)
		case "w":
			t := m.activeTier()
			m.busy = fmt.Sprintf("[T%d:%s] Decrypting same ciphertext with alternate witness w2...", t.Index, t.Name)
			m.cmp = nil
			return m, m.cmdDecrypt(2)
		case "x":
			t := m.activeTier()
			m.busy = fmt.Sprintf("[T%d:%s] Running DecUnchecked on tampered witness...", t.Index, t.Name)
			m.cmp = nil
			return m, m.cmdDecrypt(3)
		case "c":
			m.busy = "Sweeping Spectrum Tiers 1..4 (n=8 -> 384, g=2^20 -> 2^40)..."
			return m, m.cmdCompare()
		}
	}
	return m, nil
}

func padOrTrim(s string, width int) string {
	w := ansi.StringWidth(s)
	if w > width {
		return ansi.Truncate(s, width, "…")
	}
	return s + strings.Repeat(" ", width-w)
}

func fmtBytes(b int) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.2f MB", float64(b)/(1024.0*1024.0))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024.0)
	default:
		return fmt.Sprintf("%d B", b)
	}
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
	pal := palettes[m.palIdx]

	stTitle := lipgloss.NewStyle().Foreground(pal.ink).Bold(true)
	stPurple := lipgloss.NewStyle().Foreground(pal.purple).Bold(true)
	stPink := lipgloss.NewStyle().Foreground(pal.pink).Bold(true)
	stCyan := lipgloss.NewStyle().Foreground(pal.cyan).Bold(true)
	stGreen := lipgloss.NewStyle().Foreground(pal.green).Bold(true)
	stCoral := lipgloss.NewStyle().Foreground(pal.coral)
	stRed := lipgloss.NewStyle().Foreground(pal.red).Bold(true)
	stYellow := lipgloss.NewStyle().Foreground(pal.yellow).Bold(true)
	stSub := lipgloss.NewStyle().Foreground(pal.sub)
	stMuted := lipgloss.NewStyle().Foreground(pal.muted)
	stRule := lipgloss.NewStyle().Foreground(pal.rule)
	stInk := func(s string) string { return lipgloss.NewStyle().Foreground(pal.ink).Render(s) }

	sectionBar := func(title, right string, width int) string {
		left := stPurple.Render("▸ ") + stTitle.Render(title)
		r := ""
		if right != "" {
			r = " " + stMuted.Render(right)
		}
		used := ansi.StringWidth(left) + ansi.StringWidth(r) + 1
		fill := max(2, width-used)
		return left + " " + stRule.Render(strings.Repeat("─", fill)) + r
	}

	cardBox := func(lines []string, innerW int, borderCol color.Color) string {
		leftEdge := lipgloss.NewStyle().Foreground(borderCol).Background(pal.pane).Render("▏")
		rightEdge := lipgloss.NewStyle().Foreground(borderCol).Background(pal.pane).Render("▕")
		bodyBg := lipgloss.NewStyle().Background(pal.pane)
		var out []string
		for _, ln := range lines {
			padded := " " + padOrTrim(ln, innerW-4) + " "
			out = append(out, leftEdge+bodyBg.Render(padded)+rightEdge)
		}
		return strings.Join(out, "\n")
	}

	kvRow := func(k, v string, width int) string {
		keyPart := stMuted.Render(fmt.Sprintf("%-12s ", k))
		rem := max(8, width-ansi.StringWidth(keyPart))
		return keyPart + stSub.Render(ansi.Truncate(v, rem, "…"))
	}

	w := m.width
	if w < 96 {
		w = 96
	}
	if w > 146 {
		w = 146
	}
	inner := w - 2

	tier := m.activeTier()
	par := tier.Params
	pp := m.pp
	adm := pp.Admissibility()

	// --- HEADER BANNER ---
	mark := stPurple.Render("π") + " " + stTitle.Render("PRAXIS") + " " +
		stSub.Render("Witness Encryption Workbench") + " " + stMuted.Render("· ePrint 2026/2971")

	var modePill string
	switch {
	case tier.Index == 1:
		modePill = lipgloss.NewStyle().Foreground(pal.bg).Background(pal.cyan).Bold(true).Padding(0, 1).
			Render("TOY MODE · Tier 1/6")
	case tier.Index == 6:
		modePill = lipgloss.NewStyle().Foreground(pal.bg).Background(pal.green).Bold(true).Padding(0, 1).
			Render("ADVANCED MODE · Tier 6/6 · TABLE 4 (λ=100)")
	default:
		modePill = lipgloss.NewStyle().Foreground(pal.bg).Background(pal.purple).Bold(true).Padding(0, 1).
			Render(fmt.Sprintf("ADVANCED MODE · Tier %d/6 · %s", tier.Index, strings.ToUpper(tier.Name)))
	}
	themePill := lipgloss.NewStyle().Foreground(pal.sub).Background(pal.chrome).Padding(0, 1).
		Render("silkcircuit-" + pal.name)
	rightHead := modePill + " " + themePill
	gap := max(2, inner-ansi.StringWidth(mark)-ansi.StringWidth(rightHead))
	header := " " + mark + strings.Repeat(" ", gap) + rightHead

	// --- FULL-WIDTH SPECTRUM SLIDER DECK (crust/tui/slider.go style) ---
	var deckLines []string
	deckLines = append(deckLines, sectionBar(
		fmt.Sprintf("PARAMETER SPECTRUM · TIER %d/6: %s (%s)", tier.Index, strings.ToUpper(tier.Name), tier.Subtitle),
		"[ / ] slide · [p] (P1) pad · [v] theme",
		inner-4,
	))

	// Render the crust-style logarithmic slider track across all 6 stops with labeled stop ticks.
	shortNames := [6]string{"Toy", "Adv", "Med", "Hvy", "Pre", "Tbl4"}
	var tierPills []string
	for i, tr := range praxis.Spectrum {
		lbl := fmt.Sprintf("%d:%s", tr.Index, shortNames[i])
		if i == m.tierIdx {
			tierPills = append(tierPills, stCyan.Render("["+lbl+"]"))
		} else {
			tierPills = append(tierPills, stMuted.Render(lbl))
		}
	}
	pillsStr := strings.Join(tierPills, " ")
	trackW := max(24, (inner-4)-15-ansi.StringWidth(pillsStr))
	frac := float64(m.tierIdx) / float64(len(praxis.Spectrum)-1)
	thumbAt := int(math.Round(frac * float64(trackW-1)))
	var trackBuf strings.Builder
	for i := 0; i < trackW; i++ {
		isStop := false
		for sIdx := range praxis.Spectrum {
			stopPos := int(math.Round(float64(sIdx) / float64(len(praxis.Spectrum)-1) * float64(trackW-1)))
			if i == stopPos {
				isStop = true
				break
			}
		}
		switch {
		case i == thumbAt:
			trackBuf.WriteString(stPink.Render("●"))
		case i < thumbAt && isStop:
			trackBuf.WriteString(stCyan.Render("╋"))
		case i < thumbAt:
			trackBuf.WriteString(stPurple.Render("━"))
		case isStop:
			trackBuf.WriteString(stMuted.Render("┼"))
		default:
			trackBuf.WriteString(stRule.Render("─"))
		}
	}
	deckLines = append(deckLines, fmt.Sprintf("%s %s  %s",
		stMuted.Render("Scale [1..6]"),
		trackBuf.String(),
		pillsStr,
	))

	// Dual logarithmic progress meters + Theorem 5.9 Admissibility & MSIS status badges!
	nFrac := math.Log2(float64(par.NForms())/8.0) / math.Log2(4608.0/8.0)
	gLog := math.Log2(float64(par.G))
	gFrac := (gLog - 20.0) / (math.Log2(float64(praxis.Table4G)) - 20.0)

	p1Badge := stYellow.Render(fmt.Sprintf("⚠ (P1) n=%d > D=%d [press p]", adm.NForms, adm.D))
	if adm.P1NLeD && adm.P1JDeltaBounds {
		p1Badge = stGreen.Render(fmt.Sprintf("✓ (P1) n=%d ≤ D=%d", adm.NForms, adm.D))
	}
	msisBadge := stYellow.Render(fmt.Sprintf("⚠ MSIS ℓ=%d ≤ K=%d (narrow)", adm.Ell, adm.K))
	if adm.MSISWide {
		msisBadge = stGreen.Render(fmt.Sprintf("✓ MSIS %dx%d (ℓ=%d > K=%d)", adm.K, adm.Ell+1, adm.Ell, adm.K))
	}
	padIndicator := stMuted.Render("native N")
	if m.padAdmissible {
		padIndicator = stGreen.Render(fmt.Sprintf("padded N=%d", adm.N))
	}

	deckLines = append(deckLines, fmt.Sprintf("%s %s %s  %s %s %s  %s · %s",
		stMuted.Render("Lattice"),
		miniMeter(nFrac, 10, pal),
		stSub.Render(fmt.Sprintf("n=%-4d (%4dc)", par.NForms(), par.Cells())),
		stMuted.Render("Search"),
		miniMeter(gFrac, 10, pal),
		stSub.Render(fmt.Sprintf("2^%-4.1f (%3.0fb)", gLog, adm.SearchBits)),
		p1Badge,
		msisBadge,
	))
	_ = padIndicator
	deckCard := cardBox(deckLines, inner, pal.purple)

	// --- TWO COLUMNS BELOW SLIDER DECK ---
	leftW := min(52, inner*41/100)
	rightW := inner - leftW - 2

	// LEFT COLUMN: Statements & Active Engine Details
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
	qapAlg := "Schoolbook O(D^2) · coset powers"
	extDesc := fmt.Sprintf("F_q[T]/(T^%d - c0) · pow-of-2", par.NForms())
	searchAlg := "Growing-interval BSGS (392 B/step)"
	if par.Fast {
		c0 := pp.C0()
		qapAlg = "Radix-2 FFT O(|H| log |H|) · bit-rev H"
		extDesc = fmt.Sprintf("F_q[T]/(T^%d - c0) · Serret c0=%s", par.NForms(), c0.BigInt(new(big.Int)).String())
		searchAlg = "6-mul F_p Chebyshev + 57b flat table"
	}
	leftLines = append(leftLines, sectionBar("ENGINE · "+strings.ToUpper(tier.Name), "tab / [ ]", leftW-4))
	leftLines = append(leftLines, kvRow("Ring / Grid", fmt.Sprintf("dR=%d, K=%d -> %dx%d=%d cells",
		par.DR, par.K, par.K1, 3*par.K2, par.Cells()), leftW-4))
	leftLines = append(leftLines, kvRow("Extension", extDesc, leftW-4))
	leftLines = append(leftLines, kvRow("Power Chunks", fmt.Sprintf("J=%d (Δ=%d), J'=%d (Δ'=%d)",
		par.JQuo(), pp.Delta, par.JRem(), pp.DeltaPrime), leftW-4))
	leftLines = append(leftLines, kvRow("QAP Engine", qapAlg, leftW-4))
	leftLines = append(leftLines, kvRow("DL Search", searchAlg, leftW-4))

	// RIGHT COLUMN: Live QAP Geometry, Signet Vault (Tab 4), and Crypto Pipeline / Sweep Table
	var rightLines []string
	g1Count, g2Count := pp.Counts()
	estBytes := 32 + len(sc.Message) + 384 + g1Count*32 + g2Count*64
	rightLines = append(rightLines, sectionBar("QAP & CIPHERTEXT FOOTPRINT", fmt.Sprintf("Setup %v", m.setupDur.Round(100*time.Microsecond)), rightW-4))
	rightLines = append(rightLines, fmt.Sprintf("%s %s   %s %s   %s %s   %s %s",
		stMuted.Render("N="), stCoral.Render(fmt.Sprintf("%d", pp.S.N)),
		stMuted.Render("nc="), stCoral.Render(fmt.Sprintf("%d", len(pp.S.Constraints))),
		stMuted.Render("nu="), stCoral.Render(fmt.Sprintf("%d", pp.Nu)),
		stMuted.Render("|H|="), stCoral.Render(fmt.Sprintf("%d (D=%d)", pp.SubgroupSize, pp.D)),
	))
	rightLines = append(rightLines, fmt.Sprintf("%s %s G1 + %s G2 + 1 GT  ≈  %s",
		stMuted.Render("Prop 5.7:"),
		stGreen.Render(fmt.Sprintf("%d", g1Count)),
		stPurple.Render(fmt.Sprintf("%d", g2Count)),
		stYellow.Render(fmtBytes(estBytes)),
	))

	if sc.LiveSignet {
		rightLines = append(rightLines, "")
		rightLines = append(rightLines, sectionBar("BITCOIN PRIVATE SIGNET · 2-OF-2 P2TR VAULT", "challenge=51", rightW-4))
		if m.sigState == nil || m.sigState.vault == nil {
			rightLines = append(rightLines, stMuted.Render("Script: ")+stCyan.Render("tr(NUMS, {multi_a(2,Dep,Clm), pk(Dep)+CSV(6)})"))
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
			rightLines = append(rightLines, fmt.Sprintf("%s %s · %s · %s · %s",
				stMuted.Render("Guards:"),
				stSub.Render("BOTH KEYS LIVE"),
				stGreen.Render(fmt.Sprintf("Dep=%v", sv.depRug.FinalizableAlone)),
				stGreen.Render(fmt.Sprintf("Clm=%v", sv.clmEarly.FinalizableAlone)),
				stGreen.Render(fmt.Sprintf("CSV(%d)=%s", sv.csvEarly.CSVBlocks, sv.csvEarly.RejectReason)),
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
		rightLines = append(rightLines, sectionBar("SPECTRUM SWEEP · TIERS 1..4", "6-mul F_p Chebyshev", rightW-4))
		rowFmt := func(c1, c2, c3, c4, c5 string) string {
			return padOrTrim(c1, 12) + " " + padOrTrim(c2, 13) + " " + padOrTrim(c3, 10) + " " + padOrTrim(c4, 17) + " " + padOrTrim(c5, 18)
		}
		rightLines = append(rightLines, rowFmt(
			stMuted.Render("Tier"),
			stMuted.Render("n / Cells"),
			stMuted.Render("Ciphertext"),
			stMuted.Render("Enc / Dec"),
			stMuted.Render("Search (Table)"),
		))
		for _, r := range m.cmp.rows {
			tName := stSub.Render(fmt.Sprintf("T%d %s", r.tier.Index, r.tier.Name))
			if r.tier.Index-1 == m.tierIdx {
				tName = stCyan.Render(fmt.Sprintf("▸T%d %s", r.tier.Index, r.tier.Name))
			}
			rightLines = append(rightLines, rowFmt(
				tName,
				stSub.Render(fmt.Sprintf("%d / %d", r.tier.Params.NForms(), r.tier.Params.Cells())),
				stCoral.Render(fmtBytes(r.bytes)),
				stSub.Render(fmt.Sprintf("%v / %v", r.encDur.Round(time.Millisecond), r.decDur.Round(time.Millisecond))),
				stGreen.Render(fmt.Sprintf("%v (%s)", r.searchDur.Round(time.Millisecond), fmtBytes(int(r.tableBytes)))),
			))
		}
	} else {
		rightLines = append(rightLines, sectionBar("CRYPTOGRAPHIC PIPELINE", "Fig. 9 & 10", rightW-4))
		if !m.hasCT {
			rightLines = append(rightLines, stMuted.Render("Press ")+stCyan.Render("[e]")+stMuted.Render(" to encrypt at Tier ")+
				stCyan.Render(fmt.Sprintf("%d (%s)", tier.Index, tier.Name))+stMuted.Render(", or ")+
				stGreen.Render("[d]")+stMuted.Render(" / ")+stGreen.Render("[w]")+stMuted.Render(" / ")+stRed.Render("[x]")+stMuted.Render(" to run."))
		} else {
			rightLines = append(rightLines, stGreen.Render("✓ Ciphertext Sealed")+" · "+
				stCoral.Render(fmtBytes(m.encRep.Bytes))+" in "+stYellow.Render(m.encRep.EncDur.Round(time.Millisecond).String())+
				stMuted.Render(fmt.Sprintf(" · n=%d, %d cells", m.encRep.Forms, m.encRep.Cells)))
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
			workersNote := ""
			if s.Workers > 1 {
				workersNote = fmt.Sprintf(" · %d cores", s.Workers)
			}
			rightLines = append(rightLines, fmt.Sprintf("%s t=%s · baby=%d (%s) · giant=%d%s",
				stMuted.Render("Search:"),
				stYellow.Render(fmtSigned(s.Offset)),
				s.BabySteps, fmtBytes(int(s.TableBytes)),
				s.GiantSteps, workersNote,
			))
			rightLines = append(rightLines, renderSearchBar(s.Offset, pp.S.N, par.G, rightW-4, pal))
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

	rightEdgeCol := pal.rule
	if m.hasCT {
		rightEdgeCol = pal.cyan
	}
	leftCard := cardBox(leftLines, leftW, pal.rule)
	rightCard := cardBox(rightLines, rightW, rightEdgeCol)
	columns := lipgloss.JoinHorizontal(lipgloss.Top, leftCard, "  ", rightCard)

	// EVENT TRACE
	var logLines []string
	logLines = append(logLines, sectionBar("EVENT TRACE", m.busy, inner-4))
	if len(m.log) == 0 {
		logLines = append(logLines, stMuted.Render("Slide [ / ] from Tier 1 (Toy) right up to Tier 6 (Paper Table 4: n=4608, g~2^50.6); press [p] to pad N>=n for Theorem 5.9 (P1)."))
	} else {
		for _, entry := range m.log {
			logLines = append(logLines, stSub.Render("· ")+stInk(entry))
		}
	}
	logBox := cardBox(logLines, inner, pal.rule)

	// FOOTER KEY LEGEND
	keys := []string{
		stPurple.Render("[/]") + " " + stMuted.Render("scale 1..6"),
		stPurple.Render("p") + " " + stMuted.Render("(P1) pad"),
		stPurple.Render("1-4/↑↓") + " " + stMuted.Render("stmt"),
		stCyan.Render("e") + " " + stMuted.Render("encrypt"),
		stGreen.Render("d") + " " + stMuted.Render("prove w1"),
		stGreen.Render("w") + " " + stMuted.Render("alt w2"),
		stRed.Render("x") + " " + stMuted.Render("tamper"),
		stYellow.Render("c") + " " + stMuted.Render("sweep"),
		stPink.Render("v") + " " + stMuted.Render("palette"),
		stMuted.Render("q quit"),
	}
	footer := " " + strings.Join(keys, stRule.Render(" · "))

	var out strings.Builder
	out.WriteString("\n")
	out.WriteString(header + "\n\n")
	for _, row := range strings.Split(deckCard, "\n") {
		out.WriteString(" " + row + "\n")
	}
	out.WriteString("\n")
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

func miniMeter(frac float64, width int, pal silkPalette) string {
	frac = math.Max(0, math.Min(1, frac))
	filled := int(math.Round(frac * float64(width)))
	stFill := lipgloss.NewStyle().Foreground(pal.cyan)
	if frac >= 0.99 {
		stFill = lipgloss.NewStyle().Foreground(pal.green)
	} else if frac >= 0.5 {
		stFill = lipgloss.NewStyle().Foreground(pal.purple)
	}
	stEmpty := lipgloss.NewStyle().Foreground(pal.rule)
	return stFill.Render(strings.Repeat("▰", filled)) + stEmpty.Render(strings.Repeat("▱", width-filled))
}

func renderSearchBar(offset *big.Int, N int, g int64, width int, pal silkPalette) string {
	barW := max(24, width-20)
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
	stMuted := lipgloss.NewStyle().Foreground(pal.muted)
	stRule := lipgloss.NewStyle().Foreground(pal.rule)
	stGreen := lipgloss.NewStyle().Foreground(pal.green).Bold(true)
	stCyan := lipgloss.NewStyle().Foreground(pal.cyan).Bold(true)

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
	tier := 1
	if startAdvanced {
		tier = 2
	}
	return RunAtTier(tier)
}

// RunAtTier launches the interactive Praxis TUI starting at tier 1..6.
func RunAtTier(tier1Based int) error {
	m := NewAtTier(tier1Based)
	defer m.cleanup()
	_, err := tea.NewProgram(m).Run()
	return err
}
