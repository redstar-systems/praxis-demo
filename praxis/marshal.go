package praxis

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	magic       = "praxis-demo ciphertext 1\n"
	maxFieldLen = 1 << 26
)

type countingWriter struct {
	w   io.Writer
	n   int64
	err error
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	if cw.err != nil {
		return 0, cw.err
	}
	m, err := cw.w.Write(p)
	cw.n += int64(m)
	cw.err = err
	return m, err
}

func inGT(z *bn254.GT) bool {
	if z.IsZero() {
		return false
	}
	var check bn254.GT
	check.Exp(*z, fr.Modulus())
	return check.IsOne()
}

// WriteTo writes the ciphertext with compressed points.
func (ct *Ciphertext) WriteTo(w io.Writer) (int64, error) {
	if ct == nil {
		return 0, fmt.Errorf("nil ciphertext")
	}
	if len(ct.G2a) != len(ct.G2) {
		return 0, fmt.Errorf("mismatched G2 lengths (%d and %d)", len(ct.G2), len(ct.G2a))
	}
	for _, v := range []int{len(ct.Seed), len(ct.Msg), len(ct.G1), len(ct.G2)} {
		if v > maxFieldLen {
			return 0, fmt.Errorf("length %d too large", v)
		}
	}
	cw := &countingWriter{w: w}
	bw := bufio.NewWriter(cw)
	put := func(b []byte) {
		_, _ = bw.Write(b)
	}
	length := func(v int) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(v))
		put(b[:])
	}
	put([]byte(magic))
	length(len(ct.Seed))
	put(ct.Seed)
	length(len(ct.Msg))
	put(ct.Msg)
	ka := ct.Ka.Bytes()
	put(ka[:])
	length(len(ct.G1))
	for i := range ct.G1 {
		b := ct.G1[i].Bytes()
		put(b[:])
	}
	length(len(ct.G2))
	for _, part := range [][]bn254.G2Affine{ct.G2, ct.G2a} {
		for i := range part {
			b := part[i].Bytes()
			put(b[:])
		}
	}
	err := bw.Flush()
	return cw.n, err
}

// ReadCiphertext reads what WriteTo wrote. Every point is checked to be on
// its curve and in its group.
func ReadCiphertext(r io.Reader) (*Ciphertext, error) {
	br := bufio.NewReader(r)
	get := func(n int) ([]byte, error) {
		if n <= 4096 {
			b := make([]byte, n)
			_, err := io.ReadFull(br, b)
			return b, err
		}
		b, err := io.ReadAll(io.LimitReader(br, int64(n)))
		if err != nil {
			return nil, err
		}
		if len(b) < n {
			return nil, io.ErrUnexpectedEOF
		}
		return b, nil
	}
	length := func() (int, error) {
		b, err := get(4)
		if err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint32(b)
		if v > maxFieldLen {
			return 0, fmt.Errorf("length %d too large", v)
		}
		return int(v), nil
	}
	bytesField := func() ([]byte, error) {
		n, err := length()
		if err != nil {
			return nil, err
		}
		return get(n)
	}
	head, err := get(len(magic))
	if err != nil || string(head) != magic {
		return nil, fmt.Errorf("not a praxis-demo ciphertext")
	}
	ct := &Ciphertext{}
	if ct.Seed, err = bytesField(); err != nil {
		return nil, err
	}
	if ct.Msg, err = bytesField(); err != nil {
		return nil, err
	}
	ka, err := get(bn254.SizeOfGT)
	if err != nil {
		return nil, err
	}
	if err := ct.Ka.SetBytes(ka); err != nil {
		return nil, err
	}
	if !inGT(&ct.Ka) {
		return nil, fmt.Errorf("invalid GT element: subgroup check failed")
	}
	n1, err := length()
	if err != nil {
		return nil, err
	}
	ct.G1 = make([]bn254.G1Affine, 0, min(n1, 1024))
	for i := 0; i < n1; i++ {
		b, err := get(bn254.SizeOfG1AffineCompressed)
		if err != nil {
			return nil, err
		}
		var pt bn254.G1Affine
		if _, err := pt.SetBytes(b); err != nil {
			return nil, err
		}
		ct.G1 = append(ct.G1, pt)
	}
	n2, err := length()
	if err != nil {
		return nil, err
	}
	readG2Slice := func(count int) ([]bn254.G2Affine, error) {
		out := make([]bn254.G2Affine, 0, min(count, 1024))
		for i := 0; i < count; i++ {
			b, err := get(bn254.SizeOfG2AffineCompressed)
			if err != nil {
				return nil, err
			}
			var pt bn254.G2Affine
			if _, err := pt.SetBytes(b); err != nil {
				return nil, err
			}
			out = append(out, pt)
		}
		return out, nil
	}
	if ct.G2, err = readG2Slice(n2); err != nil {
		return nil, err
	}
	if ct.G2a, err = readG2Slice(n2); err != nil {
		return nil, err
	}
	return ct, nil
}
