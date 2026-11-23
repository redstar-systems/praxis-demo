# praxis-demo

A prototype of **Praxis**, the witness encryption scheme of Tse, Vanjani and
Vesely ("Praxis: Practical Witness Encryption for NP", ePrint 2026/2971).
Witness encryption encrypts a message to a statement: whoever can show the
statement true can decrypt, and nobody holds a key.

**This is a demonstration and is not secure.** It runs at reduced
parameters so that it finishes quickly, it has not been reviewed, and a
working decryption says nothing about whether a ciphertext hides its
message. Do not protect anything with it.

## Scope

The toy version: encrypt to a small puzzle written directly as a system of
quadratic equations in Boolean unknowns (the paper's sections 4 and 5), and
decrypt with a solution. A thousand unknowns is a ciphertext of roughly
20 MB.

Not in scope: the paper's instantiation (section 6), which encrypts to a
Groth16 verifier of 391,693 unknowns and makes every ciphertext 7.88 GiB.

## What will count as working

1. A valid solution decrypts to the message that was encrypted.
2. A wrong assignment does not.
3. The ciphertext's element count matches the paper's formula
   (Proposition 5.7) for the system's size.

## Where things are

| path | what |
|---|---|
| `curve/` | checks of the pairing library (BN254, gnark-crypto) |
| `docs/praxis.pdf`, `docs/praxis.txt` | the paper and its text, for reference; not in git (copy the PDF there and run `pdftotext -layout`) |

## Status

Set up 2026-11-23. The pairing check passes. Nothing of the scheme is
written yet. Next: read section 5 and appendix A in full, then the Boolean
quadratic system and its QAP (section 4).

## Run

```sh
go test ./...
```
