package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIRoundTripAndBadArgs(t *testing.T) {
	dir := t.TempDir()
	factFile := filepath.Join(dir, "fact.ct")
	if err := run([]string{"encrypt", "factor", "15", "3", "cli-factor-msg", factFile}); err != nil {
		t.Fatalf("encrypt factor: %v", err)
	}
	if err := run([]string{"decrypt", factFile, "3", "5"}); err != nil {
		t.Fatalf("decrypt factor: %v", err)
	}

	colFile := filepath.Join(dir, "col.ct")
	if err := run([]string{"encrypt", "colour", "0-1,1-2,2-0", "3", "", colFile}); err != nil {
		t.Fatalf("encrypt colour empty msg: %v", err)
	}
	if err := run([]string{"decrypt", colFile, "0,1,2"}); err != nil {
		t.Fatalf("decrypt colour: %v", err)
	}

	// Invalid arguments that return errors.
	badRuns := [][]string{
		{"encrypt", "factor", "notanumber", "4", "hi", filepath.Join(dir, "bad.ct")},
		{"encrypt", "factor", "15", "notbits", "hi", filepath.Join(dir, "bad.ct")},
		{"encrypt", "factor", "15", "0", "hi", filepath.Join(dir, "bad.ct")},
		{"encrypt", "factor", "15", "126", "hi", filepath.Join(dir, "bad.ct")},
		{"encrypt", "factor", "-15", "4", "hi", filepath.Join(dir, "bad.ct")},
		{"encrypt", "colour", "badedge", "3", "hi", filepath.Join(dir, "bad.ct")},
		{"encrypt", "colour", "0-0", "3", "hi", filepath.Join(dir, "bad.ct")},
		{"encrypt", "colour", "0-1", "0", "hi", filepath.Join(dir, "bad.ct")},
		{"encrypt", "colour", "0-1", "notint", "hi", filepath.Join(dir, "bad.ct")},
		{"decrypt", filepath.Join(dir, "missing.ct"), "3", "5"},
		{"decrypt", factFile, "3"},           // missing second factor
		{"decrypt", factFile, "3", "8"},       // 8 needs 4 bits > 3
		{"decrypt", factFile, "-3", "5"},      // negative factor
		{"decrypt", factFile, "3", "3"},       // wrong product
		{"decrypt", colFile, "0,1"},           // too few colours
		{"decrypt", colFile, "0,1,3"},         // colour out of range
		{"decrypt", colFile, "0,0,1"},         // invalid colouring
	}
	for _, args := range badRuns {
		if err := run(args); err == nil {
			t.Fatalf("expected error for args %v, got nil", args)
		}
	}

	// Corrupted files passed to decrypt.
	emptyFile := filepath.Join(dir, "empty.ct")
	_ = os.WriteFile(emptyFile, nil, 0o644)
	if err := run([]string{"decrypt", emptyFile, "3", "5"}); err == nil {
		t.Fatal("expected error on empty file")
	}

	var hugeHdr bytes.Buffer
	_ = binary.Write(&hugeHdr, binary.BigEndian, uint32((1<<20)+1))
	hugeFile := filepath.Join(dir, "hugehdr.ct")
	_ = os.WriteFile(hugeFile, hugeHdr.Bytes(), 0o644)
	if err := run([]string{"decrypt", hugeFile, "3", "5"}); err == nil {
		t.Fatal("expected error on oversized header")
	}

	var badKind bytes.Buffer
	js := []byte(`{"kind":"sat"}`)
	_ = binary.Write(&badKind, binary.BigEndian, uint32(len(js)))
	badKind.Write(js)
	badKindFile := filepath.Join(dir, "badkind.ct")
	_ = os.WriteFile(badKindFile, badKind.Bytes(), 0o644)
	if err := run([]string{"decrypt", badKindFile, "1"}); err == nil {
		t.Fatal("expected error on unknown puzzle kind")
	}
}

func TestRegressionCLIInvalidCommandsColourOverflowAndEdges(t *testing.T) {
	// Help flags succeed.
	for _, helpArg := range []string{"-h", "--help", "help"} {
		if err := run([]string{helpArg}); err != nil {
			t.Fatalf("run([%s]) failed: %v", helpArg, err)
		}
	}

	// Unrecognized commands and incomplete arguments return errors.
	for _, args := range [][]string{
		{},
		{"unknown-subcommand"},
		{"encrypt"},
		{"encrypt", "unknown", "1", "2", "3", "4"},
		{"decrypt", "somefile.ct"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("run(%v) returned nil error, expected failure", args)
		}
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "out.ct")

	// Huge colours or vertex IDs return clean errors without panicking.
	for _, args := range [][]string{
		{"encrypt", "colour", "0-1", "4611686018427387904", "hi", out},
		{"encrypt", "colour", "0-9223372036854775807", "3", "hi", out},
		{"encrypt", "colour", "0-2000000", "3", "hi", out},
	} {
		if err := run(args); err == nil {
			t.Fatalf("run(%v) succeeded, expected size/range error", args)
		}
	}

	// Crafted .ct header with huge colours/vertices in decrypt returns clean error.
	var badHdr bytes.Buffer
	js := []byte(`{"kind":"colour","vertices":1,"colours":500000000000000000}`)
	_ = binary.Write(&badHdr, binary.BigEndian, uint32(len(js)))
	badHdr.Write(js)
	badHdrFile := filepath.Join(dir, "hugecol.ct")
	_ = os.WriteFile(badHdrFile, badHdr.Bytes(), 0o644)
	if err := run([]string{"decrypt", badHdrFile, "0"}); err == nil {
		t.Fatal("expected error decrypting crafted huge-colours header")
	}

	// Malformed edges with trailing junk or extra hyphens return errors.
	for _, badEdge := range []string{"0-1junk", "0-1-2", "-1-2", "0-", "-1"} {
		if err := run([]string{"encrypt", "colour", badEdge, "2", "hi", out}); err == nil {
			t.Fatalf("encrypt colour accepted malformed edge %q", badEdge)
		}
	}
}
