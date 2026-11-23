// Command praxis encrypts a message to a puzzle and decrypts it with the
// puzzle's solution. It is a demonstration and is not secure.
package main

import (
	"bytes"
	"encoding/binary"
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
)

const usage = `praxis: witness encryption demo. NOT SECURE; do not protect anything with it.

  praxis demo
      Encrypt to two puzzles and decrypt with their solutions.

  praxis encrypt factor <n> <bits> <message> <file>
      Encrypt to "n = p * q with p and q of at most <bits> bits".
  praxis decrypt <file> <p> <q>

  praxis encrypt colour <edges> <colours> <message> <file>
      Encrypt to "this graph can be coloured with <colours> colours".
      Edges look like 0-1,1-2,2-0.
  praxis decrypt <file> <colour of vertex 0>,<of vertex 1>,...
`

// puzzle is the statement a file is encrypted to, kept at the head of the
// file so that decryption can rebuild the system.
type puzzle struct {
	Kind     string   `json:"kind"`
	N        string   `json:"n,omitempty"`
	Bits     int      `json:"bits,omitempty"`
	Vertices int      `json:"vertices,omitempty"`
	Colours  int      `json:"colours,omitempty"`
	Edges    [][2]int `json:"edges,omitempty"`
}

func (p puzzle) system() (*bqs.System, error) {
	switch p.Kind {
	case "factor":
		n, ok := new(big.Int).SetString(p.N, 10)
		if !ok {
			return nil, fmt.Errorf("bad number %q", p.N)
		}
		return bqs.Factoring(n, p.Bits, p.Bits)
	case "colour":
		return bqs.Colouring(p.Vertices, p.Colours, p.Edges)
	}
	return nil, fmt.Errorf("unknown puzzle kind %q", p.Kind)
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
	case len(args) == 1 && args[0] == "demo":
		return demo()
	case len(args) == 6 && args[0] == "encrypt" && args[1] == "factor":
		bits, err := strconv.Atoi(args[3])
		if err != nil {
			return err
		}
		return encrypt(puzzle{Kind: "factor", N: args[2], Bits: bits}, args[4], args[5])
	case len(args) == 6 && args[0] == "encrypt" && args[1] == "colour":
		p := puzzle{Kind: "colour"}
		for _, e := range strings.Split(args[2], ",") {
			var a, b int
			if _, err := fmt.Sscanf(e, "%d-%d", &a, &b); err != nil {
				return fmt.Errorf("bad edge %q", e)
			}
			p.Edges = append(p.Edges, [2]int{a, b})
			p.Vertices = max(p.Vertices, a+1, b+1)
		}
		var err error
		if p.Colours, err = strconv.Atoi(args[3]); err != nil {
			return err
		}
		return encrypt(p, args[4], args[5])
	case len(args) >= 3 && args[0] == "decrypt":
		return decrypt(args[1], args[2:])
	}
	fmt.Print(usage)
	return nil
}

func encrypt(p puzzle, msg, file string) error {
	s, err := p.system()
	if err != nil {
		return err
	}
	pp, err := praxis.Setup(praxis.Toy, s)
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
	pp, err := praxis.Setup(praxis.Toy, s)
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

func demo() error {
	fmt.Println("Praxis witness encryption, demonstration parameters. NOT SECURE.")
	p, q := big.NewInt(4294967291), big.NewInt(4294967279) // two primes just below 2^32
	fact := puzzle{Kind: "factor", N: new(big.Int).Mul(p, q).String(), Bits: 32}
	col := puzzle{Kind: "colour", Vertices: 10, Colours: 3, Edges: [][2]int{
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
		pp, err := praxis.Setup(praxis.Toy, s)
		if err != nil {
			return err
		}
		msg := []byte("the solution was the key")
		start := time.Now()
		ct, err := praxis.Enc(pp, msg)
		if err != nil {
			return err
		}
		g1, g2 := pp.Counts()
		fmt.Printf("  encrypted in %v: %d bytes (%d + %d group elements)\n",
			time.Since(start).Round(time.Millisecond), ct.Size(), g1, g2)

		w := c.w()
		start = time.Now()
		got, err := praxis.Dec(pp, ct, w)
		if err != nil {
			return err
		}
		fmt.Printf("  decrypted with the solution in %v: %q\n", time.Since(start).Round(time.Millisecond), got)

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
	return fmt.Sprintf("noise (%x...)", got[:6])
}
