# praxis-demo

A prototype of **Praxis**, the witness encryption scheme of Tse, Vanjani and
Vesely ("Praxis: Practical Witness Encryption for NP", ePrint 2026/2971).
Witness encryption encrypts a message to a statement: whoever can show the
statement true can decrypt, and nobody holds a key.

**This is a demonstration and is not secure.** It runs at parameters far
below the paper's, nothing in it runs in constant time, it has not been
reviewed, and a working decryption says nothing about whether a ciphertext
hides its message. Do not protect anything with it.

## Try it

![A recording of the demo](docs/demo.gif)

Open the interactive Charm v2 workbench (supports switching live between **Toy** and **Advanced** modes across Factoring, Petersen 3-Colouring, and 3-SAT):

```sh
go run ./cmd/praxis tui
```

Or run the CLI walkthrough in either Toy or Advanced mode:

```sh
go run ./cmd/praxis demo
go run ./cmd/praxis demo --advanced
```

encrypts a message to two puzzles and decrypts each with its solution. To
encrypt to a number, so that whoever knows its factors can read the message:

```sh
go run ./cmd/praxis encrypt factor 3214085717 16 "hello" hello.ct
go run ./cmd/praxis decrypt hello.ct 64283 49999
```

or to a graph (pass `--advanced` to enable multi-chunk powers, FFT QAP, and sign-class fingerprint search), so that whoever can colour it can:

```sh
go run ./cmd/praxis encrypt --advanced colour 0-1,1-2,2-0 3 "hello" hello.ct
go run ./cmd/praxis decrypt hello.ct 0,1,2
```

## What is here

The whole scheme as the paper specifies it in Figures 9 and 10, in two selectable modes:

- **Toy mode (`praxis.Toy`):** Eight forms ($n = 8$) and twelve cells ($2 \times 6$ grid), 20-bit secrets, unsplit power lists ($J = J' = 1$), schoolbook QAP interpolation, and growing-interval BSGS.
- **Advanced mode (`praxis.Advanced`):** General even Serret extensions $n = (K+1)d_R \mid (q - 1)$ ($n = 24$ forms, 36 cells in a $4 \times 9$ grid), 24-bit secrets, multi-chunk quotient and remainder powers ($J = 4, J' = 2$, Section 5.2), bit-reversed subgroup placement in $\mathcal{H}$ with $O(|\mathcal{H}| \log |\mathcal{H}|)$ radix-2 FFT / Hensel–Newton polynomial division (Section 4.4), and outward search on $\mathbb{G}_T$ sign classes $\{V, V^{-1}\}$ using 64-bit $\mathbb{F}_{p^6}$ fingerprints (Section 5.2).

What still differs from the paper's full 100-bit instantiation:

- **Interactive parameter scale.** Eight to twenty-four forms and 20–24-bit secrets instead of 4,608 forms, 6,912 copies, and ~50-bit secrets, so encryption and decryption run in ~50–120 ms locally without 12 GB precomputation tables.
- **Not constant-time, and hand-built BQS statements** (factoring, graph colouring, and 3-SAT gate reductions) rather than Section 6's 391,693-unknown Groth16 verifier (7.88 GiB ciphertexts).

## What the tests show

1. A solution decrypts to the message that was encrypted, for both puzzles
   and for six sets of parameters, including the paper's Figure 5.
2. Two different solutions of one system both decrypt one ciphertext.
3. A wrong assignment does not decrypt, even when decryption's algebra is
   run on it without checking it first.
4. The divisions decryption relies on are exact for a solution and for no
   assignment one flip away from one (the paper's Lemma 4.7).
5. The ciphertext's element counts equal the paper's formulas
   (Proposition 5.7).

Point 1 is the strong check. Decryption only recovers the key if every term
the paper says cancels does cancel, so a mistake in almost any formula shows
up as a failed decryption. None of this is evidence of security.

## Where things are

| path | what |
|---|---|
| `bqs/` | Boolean quadratic systems, padding, and three puzzles: factoring, graph colouring, and 3-SAT |
| `poly/` | schoolbook and radix-2 FFT / Hensel–Newton polynomial arithmetic over BN254's scalar field |
| `praxis/setup.go` | QAP encoding and bit-reversed subgroup $\mathcal{H}$ placement (Definition 4.6, Lemma 4.7, Section 4.4) |
| `praxis/forms.go` | forms, extension-field weights, and the grid of copies (Definition 5.1, Section 5.1) |
| `praxis/enc.go` | encryption with optional multi-chunk powers (Figure 9, Section 5.2) |
| `praxis/dec.go`, `praxis/search_fast.go` | decryption, growing-interval BSGS, and outward $\mathbb{G}_T$ sign-class 64-bit fingerprint search (Figure 10, Section 5.2) |
| `praxis/marshal.go` | compressed ciphertext serialization with curve and $\mathbb{G}_T$ subgroup checks |
| `tui/` | interactive Charm v2 workbench comparing Toy and Advanced modes |
| `cmd/praxis/` | the command-line tool (`tui`, `demo`, `encrypt`, `decrypt`) |
| `docs/demo.tape`, `docs/demo.gif` | the recording above and its script; re-record with `vhs docs/demo.tape` |
| `curve/` | checks of the pairing library (BN254, gnark-crypto) |
| `docs/praxis.pdf`, `docs/praxis.txt` | the paper and its text, for reference; not in git (copy the PDF there and run `pdftotext -layout`) |

## Size

With the demo's parameters a ciphertext is about 1.7 KB per unknown plus
about 20 KB fixed. The paper's parameters cost about 20 KB per unknown.

## Run the tests

```sh
go test ./...
```
