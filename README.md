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

```sh
go run ./cmd/praxis demo
```

encrypts a message to two puzzles and decrypts each with its solution. To
encrypt to a number, so that whoever knows its factors can read the message:

```sh
go run ./cmd/praxis encrypt factor 3214085717 16 "hello" hello.ct
go run ./cmd/praxis decrypt hello.ct 64283 49999
```

or to a graph, so that whoever can colour it can:

```sh
go run ./cmd/praxis encrypt colour 0-1,1-2,2-0 3 "hello" hello.ct
go run ./cmd/praxis decrypt hello.ct 0,1,2
```

The 32-bit factoring demo makes a ciphertext of 129 KB and takes about 60 ms
each way.

## What is here

The whole scheme as the paper specifies it in Figures 9 and 10: the
polynomial encoding of a system with a coset per equation, the forms from a
seeded ring matrix, the weights from an extension field, the grid of copies
with shared factors, the tie masks and their cancellation, the centered
sampler, and the search. Statements are systems of quadratic equations in
unknowns that must each be 0 or 1 (the paper's sections 4 and 5).

What differs from the paper:

- **Parameters.** Eight forms and twelve copies where the paper has 4,608
  and 6,912; secret integers of 20 bits where the paper has about 50. The
  lattice problem behind the forms is trivial at this size.
- **One chunk of powers.** The paper splits two lists of powers into chunks
  to save 2 percent of size; this takes the unsplit case, which the paper
  also defines.
- **Slow polynomial arithmetic.** Quadratic time, no fast transforms. Fine
  to a few thousand evaluation points.
- **A plain search.** Baby steps and giant steps over the whole range, not
  the paper's outward search with fingerprints.
- **Not the paper's instantiation** (section 6), which encrypts to a Groth16
  verifier of 391,693 unknowns and makes every ciphertext 7.88 GiB. This
  encrypts to small systems written by hand.

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
| `bqs/` | systems of equations, and the two puzzles: factoring and graph colouring |
| `poly/` | polynomial arithmetic over the curve's scalar field |
| `praxis/setup.go` | the polynomial encoding of a system (Definition 4.6, Lemma 4.7) |
| `praxis/forms.go` | forms, weights and the grid of copies (Definition 5.1, section 5.1) |
| `praxis/enc.go` | encryption (Figure 9) |
| `praxis/dec.go` | decryption and the search (Figure 10) |
| `praxis/marshal.go` | the ciphertext as a file |
| `cmd/praxis/` | the command-line tool |
| `curve/` | checks of the pairing library (BN254, gnark-crypto) |
| `docs/praxis.pdf`, `docs/praxis.txt` | the paper and its text, for reference; not in git (copy the PDF there and run `pdftotext -layout`) |

## Size

With the demo's parameters a ciphertext is about 1.7 KB per unknown plus
about 20 KB fixed. The paper's parameters cost about 20 KB per unknown.

## Run the tests

```sh
go test ./...
```
