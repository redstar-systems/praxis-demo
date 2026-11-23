package praxis

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

const magic = "praxis-demo ciphertext 1\n"

// WriteTo writes the ciphertext with compressed points.
func (ct *Ciphertext) WriteTo(w io.Writer) (int64, error) {
	bw := bufio.NewWriter(w)
	var n int64
	put := func(b []byte) {
		m, _ := bw.Write(b)
		n += int64(m)
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
	return n, bw.Flush()
}

// ReadCiphertext reads what WriteTo wrote. Every point is checked to be on
// its curve and in its group.
func ReadCiphertext(r io.Reader) (*Ciphertext, error) {
	br := bufio.NewReader(r)
	get := func(n int) ([]byte, error) {
		b := make([]byte, n)
		_, err := io.ReadFull(br, b)
		return b, err
	}
	length := func() (int, error) {
		b, err := get(4)
		if err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint32(b)
		if v > 1<<26 {
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
	n1, err := length()
	if err != nil {
		return nil, err
	}
	ct.G1 = make([]bn254.G1Affine, n1)
	for i := range ct.G1 {
		b, err := get(bn254.SizeOfG1AffineCompressed)
		if err != nil {
			return nil, err
		}
		if _, err := ct.G1[i].SetBytes(b); err != nil {
			return nil, err
		}
	}
	n2, err := length()
	if err != nil {
		return nil, err
	}
	ct.G2 = make([]bn254.G2Affine, n2)
	ct.G2a = make([]bn254.G2Affine, n2)
	for _, part := range [][]bn254.G2Affine{ct.G2, ct.G2a} {
		for i := range part {
			b, err := get(bn254.SizeOfG2AffineCompressed)
			if err != nil {
				return nil, err
			}
			if _, err := part[i].SetBytes(b); err != nil {
				return nil, err
			}
		}
	}
	return ct, nil
}
