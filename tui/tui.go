// Package tui implements an interactive Charm v2 workbench for exploring Praxis
// witness encryption across Toy and Advanced (Figures 9–10) modes.
package tui

import (
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
)

// SilkCircuit Neon palette (matching cherry-pi's surface/ink/accent hierarchy).
var (
	colBg       = lipgloss.Color("#12101a")
	colPane     = lipgloss.Color("#181425")
	colHeader   = lipgloss.Color("#221e32")
	colRule     = lipgloss.Color("#39305c")
	colInk      = lipgloss.Color("#f8f8f2")
	colSub      = lipgloss.Color("#e9d5ff")
	colMuted    = lipgloss.Color("#768d8d")
	colPurple   = lipgloss.Color("#e135ff")
	colCyan     = lipgloss.Color("#80ffea")
	colGreen    = lipgloss.Color("#50fa7b")
	colCoral    = lipgloss.Color("#ff6ac1")
	colRed      = lipgloss.Color("#ff6363")
	colYellow   = lipgloss.Color("#f1fa8c")

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
	Name      string
	Tag       string
	Statement string
	Message   string
	RawSys    *bqs.System
	Witness1  []bool
	Wit1Desc  string
	Witness2  []bool
	Wit2Desc  string
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
	}
}

type decOutcome struct {
	label     string
	witDesc   string
	witWeight int
	unchecked bool
	plaintext string
	err       error
	rep       praxis.DecReport
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
}

type decDoneMsg struct {
	out decOutcome
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
		width:     112,
		height:    34,
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
	}
}

func (m *Model) pushLog(entry string) {
	m.log = append(m.log, entry)
	if len(m.log) > 4 {
		m.log = m.log[len(m.log)-4:]
	}
}

func (m *Model) Init() tea.Cmd { return nil }

func (m *Model) cmdEncrypt() tea.Cmd {
	pp := m.pp
	msg := []byte(m.scenarios[m.cursor].Message)
	return func() tea.Msg {
		ct, rep, err := praxis.EncDetailed(pp, msg)
		return encDoneMsg{ct: ct, rep: rep, err: err}
	}
}

func (m *Model) cmdDecrypt(which int) tea.Cmd {
	sc := m.scenarios[m.cursor]
	pp := m.pp
	ct := m.ct
	return func() tea.Msg {
		// Auto-encrypt first if user presses d/w/x before encrypting.
		if ct == nil {
			var err error
			ct, _, err = praxis.EncDetailed(pp, []byte(sc.Message))
			if err != nil {
				return decDoneMsg{out: decOutcome{err: err}}
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
		return decDoneMsg{out: decOutcome{
			label:     label,
			witDesc:   desc,
			witWeight: wt,
			unchecked: unchecked,
			plaintext: string(plain),
			err:       err,
			rep:       rep,
		}}
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
		if msg.err != nil {
			m.pushLog("encrypt error: " + msg.err.Error())
			return m, nil
		}
		m.ct = msg.ct
		m.encRep = msg.rep
		m.hasCT = true
		m.lastDec = nil
		modeTag := "TOY"
		if m.advanced {
			modeTag = "ADV"
		}
		m.pushLog(fmt.Sprintf("[%s] Encrypted %s -> %s (%d G1 + %d G2, %v)",
			modeTag, m.scenarios[m.cursor].Name, fmtBytes(msg.rep.Bytes),
			msg.rep.G1, msg.rep.G2, msg.rep.EncDur.Round(time.Millisecond)))
		return m, nil

	case decDoneMsg:
		m.busy = ""
		o := msg.out
		m.lastDec = &o
		if o.err == nil {
			m.pushLog(fmt.Sprintf("Decrypted via %s in %v (offset t=%s, %d+%d steps)",
				o.label, o.rep.TotalDur.Round(time.Millisecond),
				fmtSigned(o.rep.Search.Offset), o.rep.Search.BabySteps, o.rep.Search.GiantSteps))
		} else {
			m.pushLog(fmt.Sprintf("Rejected %s in %v (exact QAP=%v -> no key found)",
				o.label, o.rep.TotalDur.Round(time.Millisecond), o.rep.ExactQAP))
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
		case "1", "2", "3":
			idx := int(msg.String()[0] - '1')
			if idx >= 0 && idx < len(m.scenarios) {
				m.cursor = idx
				m.cmp = nil
				m.runSetupSync()
			}
		case "e", "enter":
			m.busy = "Encrypting statement (Fig. 9)..."
			m.cmp = nil
			return m, m.cmdEncrypt()
		case "d":
			if !m.hasCT {
				// Encrypt synchronously first so both ct and decryption stay stored.
				ct, rep, err := praxis.EncDetailed(m.pp, []byte(m.scenarios[m.cursor].Message))
				if err == nil {
					m.ct, m.encRep, m.hasCT = ct, rep, true
				}
			}
			m.busy = "Decrypting with witness w1 (Fig. 10)..."
			m.cmp = nil
			return m, m.cmdDecrypt(1)
		case "w":
			if !m.hasCT {
				ct, rep, err := praxis.EncDetailed(m.pp, []byte(m.scenarios[m.cursor].Message))
				if err == nil {
					m.ct, m.encRep, m.hasCT = ct, rep, true
				}
			}
			m.busy = "Decrypting same ciphertext with alternate witness w2..."
			m.cmp = nil
			return m, m.cmdDecrypt(2)
		case "x":
			if !m.hasCT {
				ct, rep, err := praxis.EncDetailed(m.pp, []byte(m.scenarios[m.cursor].Message))
				if err == nil {
					m.ct, m.encRep, m.hasCT = ct, rep, true
				}
			}
			m.busy = "Running DecUnchecked on tampered witness..."
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
		padded := " " + padOrTrim(ln, innerW-2) + " "
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

	// Two columns: Left = Statements & Mode Spec; Right = Live QAP, Chunks & Telemetry.
	leftW := min(52, inner*42/100)
	rightW := inner - leftW - 2

	// --- LEFT COLUMN ---
	var leftLines []string
	leftLines = append(leftLines, sectionBar("NP STATEMENTS", "1-3 / ↑↓", leftW-2))
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
	leftLines = append(leftLines, sectionBar("ACTIVE ENGINE · "+modeName, "tab", leftW-2))
	leftLines = append(leftLines, kvRow("Ring / Grid", fmt.Sprintf("dR=%d, K=%d -> %d forms, %dx%d=%d cells",
		par.DR, par.K, par.NForms(), par.K1, 3*par.K2, par.Cells()), leftW-2))
	leftLines = append(leftLines, kvRow("Extension", extDesc, leftW-2))
	leftLines = append(leftLines, kvRow("Power Chunks", fmt.Sprintf("J=%d quo, J'=%d rem", par.JQuo(), par.JRem()), leftW-2))
	leftLines = append(leftLines, kvRow("QAP Engine", qapAlg, leftW-2))
	leftLines = append(leftLines, kvRow("Secret Range", fmt.Sprintf("g = 2^%d (%d)", int(math.Log2(float64(par.G))), par.G), leftW-2))
	leftLines = append(leftLines, kvRow("DL Search", searchAlg, leftW-2))

	// --- RIGHT COLUMN ---
	var rightLines []string
	pp := m.pp
	g1Count, g2Count := pp.Counts()
	c0 := pp.C0()
	c0Int := c0.BigInt(new(big.Int))
	rightLines = append(rightLines, sectionBar("QAP & CHUNK GEOMETRY", fmt.Sprintf("Setup %v", m.setupDur.Round(100*time.Microsecond)), rightW-2))
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

	rightLines = append(rightLines, "")
	if m.cmp != nil {
		c := m.cmp
		colRow := func(c1, c2, c3 string) string {
			return "  " + padOrTrim(c1, 16) + "  " + padOrTrim(c2, 27) + "  " + padOrTrim(c3, 29)
		}
		rightLines = append(rightLines, sectionBar("TOY vs ADVANCED BENCHMARK", "live run", rightW-2))
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
		rightLines = append(rightLines, sectionBar("CRYPTOGRAPHIC PIPELINE", "Fig. 9 & 10", rightW-2))
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
			fpNote := ""
			if s.Algorithm == "outward-sign-fp64" {
				fpNote = fmt.Sprintf(" · FP64 hits=%d (false=%d)", s.FingerprintHits, s.FalsePositives)
			}
			rightLines = append(rightLines, fmt.Sprintf("%s c_w=%s · t=%s · baby=%d (%s) · giant=%d%s",
				stMuted.Render("Search:"),
				s.Center.String(),
				stYellow.Render(fmtSigned(s.Offset)),
				s.BabySteps, fmtBytes(int(s.TableBytes)),
				s.GiantSteps, fpNote,
			))
			rightLines = append(rightLines, renderSearchBar(s.Offset, pp.S.N, par.G, rightW-4))
			if o.err == nil {
				rightLines = append(rightLines, stGreen.Render("🔓 UNLOCKED: ")+stTitle.Render(fmt.Sprintf("%q", o.plaintext)))
			} else {
				rightLines = append(rightLines, stRed.Render("✗ REJECTED: ")+stSub.Render(o.err.Error()))
			}
		}
	}

	// Pad columns to equal height.
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

	// Activity log strip
	var logLines []string
	logLines = append(logLines, sectionBar("EVENT TRACE", m.busy, inner-2))
	if len(m.log) == 0 {
		logLines = append(logLines, stMuted.Render("Ready. Toggle [tab] Toy/Advanced, [e] Encrypt, [d] Witness w1, [w] Alternate w2, [x] Tamper, [c] Benchmark."))
	} else {
		for _, entry := range m.log {
			logLines = append(logLines, stSub.Render("· ")+stInk(entry))
		}
	}
	logBox := cardBox(logLines, inner, false)

	// Footer key legend (cherry-pi style)
	keys := []string{
		stPurple.Render("1-3/↑↓") + " " + stMuted.Render("statement"),
		stPurple.Render("tab") + " " + stMuted.Render("toy/advanced"),
		stCyan.Render("e") + " " + stMuted.Render("encrypt"),
		stGreen.Render("d") + " " + stMuted.Render("decrypt w1"),
		stGreen.Render("w") + " " + stMuted.Render("alt witness w2"),
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

// renderSearchBar visualizes [-3*sigma, +3*sigma] around center c_w and marks where t landed.
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
	_, err := tea.NewProgram(New(startAdvanced)).Run()
	return err
}
