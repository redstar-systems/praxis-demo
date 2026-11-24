package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func sendKey(m tea.Model, k string) *Model {
	var msg tea.KeyPressMsg
	switch k {
	case "tab":
		msg = tea.KeyPressMsg{Code: tea.KeyTab}
	case "enter":
		msg = tea.KeyPressMsg{Code: tea.KeyEnter}
	default:
		r := []rune(k)[0]
		msg = tea.KeyPressMsg{Code: r, Text: k}
	}
	next, cmd := m.Update(msg)
	for cmd != nil {
		res := cmd()
		if res == nil {
			break
		}
		if _, isQuit := res.(tea.QuitMsg); isQuit {
			break
		}
		next, cmd = next.Update(res)
	}
	return next.(*Model)
}

func TestTUIWorkflowSpectrumSliderAndAdmissibility(t *testing.T) {
	m := New(true)
	m.Update(tea.WindowSizeMsg{Width: 132, Height: 40})

	// Initial render shows ADVANCED MODE (Tier 2).
	v := m.View()
	if !strings.Contains(v.Content, "ADVANCED MODE") || !strings.Contains(v.Content, "PARAMETER SPECTRUM") {
		t.Fatal("expected ADVANCED MODE and PARAMETER SPECTRUM in initial view")
	}

	// Encrypt and decrypt with both w1 and w2, then tamper x on Petersen colouring.
	m = sendKey(m, "2")
	m = sendKey(m, "e")
	if !m.hasCT {
		t.Fatal("expected ciphertext after pressing e")
	}
	m = sendKey(m, "d")
	if m.lastDec == nil || m.lastDec.err != nil {
		t.Fatalf("expected w1 decryption success, got %+v", m.lastDec)
	}
	m = sendKey(m, "w")
	if m.lastDec == nil || m.lastDec.err != nil {
		t.Fatalf("expected w2 decryption success, got %+v", m.lastDec)
	}
	m = sendKey(m, "x")
	if m.lastDec == nil || m.lastDec.err == nil {
		t.Fatal("expected tampered witness to fail")
	}

	// Slide up to Tier 3 (n=96), toggle [p] (P1)/MSIS padding, verify admissibility turns green and decrypts.
	m = sendKey(m, "]")
	if m.activeTier().Index != 3 {
		t.Fatalf("expected Tier 3 after ], got %d", m.activeTier().Index)
	}
	m = sendKey(m, "p")
	if !m.pp.Admissibility().FullyAdmissible() {
		t.Fatalf("expected [p] to make Tier 3 FullyAdmissible: %+v", m.pp.Admissibility())
	}
	m = sendKey(m, "d")
	if m.lastDec == nil || m.lastDec.err != nil {
		t.Fatalf("expected padded admissible Tier 3 decryption success, got %+v", m.lastDec)
	}
	m = sendKey(m, "p") // restore native N

	// Slide all the way up to Tier 6 (Table 4: n=4608) and verify header badge & SilkCircuit palette cycling.
	m = sendKey(m, "]")
	m = sendKey(m, "]")
	m = sendKey(m, "]")
	if m.activeTier().Index != 6 {
		t.Fatalf("expected Tier 6 at top of slider, got %d", m.activeTier().Index)
	}
	m = sendKey(m, "v")
	v6 := m.View()
	if !strings.Contains(v6.Content, "TABLE 4") || !strings.Contains(v6.Content, "silkcircuit-vibrant") {
		t.Fatal("expected TABLE 4 and silkcircuit-vibrant in Tier 6 view")
	}

	// Toggle back to Toy via tab, run 4-tier sweep on 3-SAT, and check Signet tab (4).
	m = sendKey(m, "tab")
	if m.advanced {
		t.Fatal("expected tab to toggle back to Toy mode")
	}
	m = sendKey(m, "3")
	m = sendKey(m, "c")
	if m.cmp == nil || len(m.cmp.rows) != 4 || m.cmp.advTable >= m.cmp.toyTable {
		t.Fatalf("unexpected sweep comparison result: %+v", m.cmp)
	}
	m = sendKey(m, "4")
	v4 := m.View()
	if !strings.Contains(v4.Content, "BITCOIN PRIVATE SIGNET") {
		t.Fatal("expected BITCOIN PRIVATE SIGNET section on tab 4")
	}
}
