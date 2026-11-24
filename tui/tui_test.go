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

func TestTUIWorkflowToyAndAdvanced(t *testing.T) {
	m := New(true)
	m.Update(tea.WindowSizeMsg{Width: 116, Height: 36})

	// Initial render shows ADVANCED MODE.
	v := m.View()
	if !strings.Contains(v.Content, "ADVANCED MODE") {
		t.Fatal("expected ADVANCED MODE in initial view")
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

	// Toggle to Toy mode and run benchmark comparison on 3-SAT.
	m = sendKey(m, "tab")
	if m.advanced {
		t.Fatal("expected tab to toggle to Toy mode")
	}
	m = sendKey(m, "3")
	m = sendKey(m, "c")
	if m.cmp == nil || m.cmp.advTable >= m.cmp.toyTable {
		t.Fatalf("expected compact fingerprint table in comparison: %+v", m.cmp)
	}

	// Switch to Signet Bridge Vault tab (4) and verify Signet vault panel renders.
	m = sendKey(m, "4")
	v4 := m.View()
	if !strings.Contains(v4.Content, "BITCOIN PRIVATE SIGNET") {
		t.Fatal("expected BITCOIN PRIVATE SIGNET section on tab 4")
	}
}
