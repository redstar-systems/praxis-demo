# praxis-demo

An executable Go prototype of **Praxis**, the witness encryption scheme for NP of Tse, Vanjani, and Vesely (*"Praxis: Practical Witness Encryption for NP"*, IACR ePrint 2026/2971), built over BN254 (`gnark-crypto`).

Witness encryption encrypts a message directly to a mathematical statement $S$—no secret or public key pair is ever generated. Anyone holding a witness $w$ proving $S$ is true can compute the target-group key $[\kappa]_T$ from the ciphertext and decrypt; if $S$ is false, the ciphertext hides the message. While [`psivesely/praxis-lean`](https://github.com/psivesely/praxis-lean) formalizes the scheme's correctness and generic-group extractability proofs in Lean 4, it does not generate ciphertexts or execute encryption/decryption; this repository implements the full runnable algebra of Figures 9 and 10 on BN254.

> [!CAUTION]
> **This software is an educational prototype and is NOT SECURE.**
> - Both `Toy` ($n = 8, g = 2^{20}$) and `Advanced` ($n = 24, g = 2^{24}$) run at **interactive parameters far below cryptographic scale**: the underlying Module-SIS lattice instances have tiny rank/dimension and can be broken in milliseconds, and the 20–24-bit secret integers are trivially searchable without a witness.
> - Nothing in this repository runs in constant time or defends against side-channel attacks, it has not undergone a cryptographic security audit, and `Params.Validate()` checks algebraic well-formedness rather than the paper's generic-group security inequalities (P1)–(P5).
> - Passing decryption tests verify **algebraic completeness** (that every QAP, tie, and cross-term cancels as proved in Lemma 5.4 and Theorem 5.6)—they say **nothing** about whether a ciphertext hides its message. **Do not protect real data or funds with this code.**

---

## Interactive Demo & VHS Tape

![Interactive Praxis TUI Workbench](docs/demo.gif)

The recording above is produced reproducibly from [`docs/demo.tape`](docs/demo.tape) using [Charm VHS](https://github.com/charmbracelet/vhs). It launches `praxis tui` in **Advanced mode** and walks through:

1. **Semiprime Factoring (R1CS, $F_{\max} = 1$):** Encrypts a message to $18{,}446{,}743{,}979{,}220{,}271{,}189 = p \cdot q$ ($p, q < 2^{32}$, 64 unknowns) with $J = 4, J' = 2$ chunked powers and unlocks it using the prime factors via outward $\mathbb{G}_T$ sign-class fingerprint search.
2. **Petersen Graph 3-Colouring (Coset BQS, $F_{\max} = 3, \nu = 4$):** Encrypts to 3-colourability of the Petersen graph, unlocks the ciphertext with one colouring $w_1$, and unlocks the **exact same ciphertext** with an independent permuted colouring $w_2$ (demonstrating keyless witness-indistinguishable decryption).
3. **3-SAT Boolean Gate Circuit:** Runs a live side-by-side **Toy vs. Advanced** benchmark on a 6-variable, 8-clause 3-SAT circuit (comparing ciphertext element counts, runtimes, and the ~20× reduction in baby-step table memory from 64-bit $\mathbb{F}_{p^6}$ sign-class fingerprints).
4. **Operator-Free 2-of-2 Bitcoin Private Signet Taproot Vault (`signetchallenge=51`):** Locks `1.00000000 sBTC` in a 2-of-2 Tapscript output `tr(NUMS, multi_a(2, Depositor, Claimer))` (`OP_CHECKSIGADD` under BIP-341's unspendable NUMS internal key), keeping **both parties' private keys live** so nobody is asked to trust that a key file was deleted. Verifies on Bitcoin Core that neither Depositor nor Claimer can finalize a spend alone, seals Depositor's 1-of-2 partial PSBT inside a Praxis ciphertext under `bqs.BridgeBurn` (Depositor then goes offline), rejects a forged burn proof while confirming the Signet UTXO stays unspent, and finally proves a valid L2 burn preimage so Claimer decrypts Depositor's partial PSBT, co-signs the 2nd Schnorr signature, finalizes the 4-item Tapscript witness, broadcasts, and mines the settlement block on Signet.

To re-record [`docs/demo.gif`](docs/demo.gif) from the repository root (requires `vhs`, `ffmpeg`, `ttyd`, and `bitcoind`):

```sh
vhs docs/demo.tape
```

<details>
<summary>View <code>docs/demo.tape</code></summary>

```tape
Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1480
Set Height 900
Set Padding 20
Set Framerate 24
Set TypingSpeed 35ms
Set Theme {"background":"#12101a","foreground":"#f8f8f2","cursor":"#e135ff"}

Hide
Type@0ms "export PRAXIS_BIN=$(mktemp -d) && go build -o $PRAXIS_BIN/praxis ./cmd/praxis && export PATH=$PRAXIS_BIN:$PATH && export PS1='$ ' && clear"
Enter
Sleep 4s
Show

Type "praxis tui"
Enter
Wait+Screen@10s /NP STATEMENTS/
Sleep 1.2s

# 1. Semiprime Factoring (R1CS) in Advanced Mode: encrypt & unlock with (p, q).
Type "e"
Wait+Screen@10s /Ciphertext Sealed/
Sleep 800ms
Type "d"
Wait+Screen@10s /UNLOCKED:/
Sleep 1.8s

# 2. Petersen Graph 3-Colouring (nu=4 cosets): unlock with w1, then alternate w2.
Type "2"
Sleep 600ms
Type "d"
Wait+Screen@10s /Witness w1:/
Sleep 1.6s
Type "w"
Wait+Screen@10s /Alternate w2:/
Sleep 1.6s

# 3. 3-SAT Gate Circuit: live side-by-side Toy vs Advanced benchmark.
Type "3"
Sleep 600ms
Type "c"
Wait+Screen@15s /TOY vs ADVANCED BENCHMARK/
Sleep 2.2s

# 4. Operator-Free 2-of-2 Bitcoin Private Signet Taproot Bridge Vault.
Type "4"
Sleep 1s
Type "e"
Wait+Screen@60s /BOTH KEYS LIVE/
Sleep 2.2s
Type "x"
Wait+Screen@15s /still UNSPENT on Signet/
Sleep 2.5s
Type "d"
Wait+Screen@60s /SWEPT ON SIGNET:/
Sleep 3.5s

Type "q"
Sleep 600ms

Hide
Type@0ms "rm -rf $PRAXIS_BIN"
Enter
```

</details>

---

## Quick Start

### Interactive Charm v2 Workbench

```sh
go run ./cmd/praxis tui          # start in Advanced mode (press Tab to toggle Toy/Advanced)
go run ./cmd/praxis tui --toy    # start in Toy mode
```

Inside the TUI: `1`–`4` or `↑`/`↓` selects the NP statement (including `4` for the live **2-of-2 Bitcoin Private Signet Taproot Bridge Vault**), `Tab` toggles **Toy** $\leftrightarrow$ **Advanced**, `e` encrypts (or funds a fresh 2-of-2 Signet P2TR vault and seals Depositor's 1-of-2 partial PSBT), `d` decrypts with primary witness $w_1$ (and co-signs/sweeps on Signet), `w` decrypts the same ciphertext with alternate witness $w_2$, `x` flips a bit of $w_1$ and runs `DecUnchecked`, `c` benchmarks Toy vs. Advanced side by side, and `q` quits.

### Operator-Free 2-of-2 Bitcoin Private Signet Bridge Demo

Run the end-to-end 2-of-2 Bitcoin Taproot (`P2TR` / `OP_CHECKSIGADD`) vault withdrawal against a local private Signet (`signetchallenge=51`, auto-attaching to a local Signet RPC or launching an isolated ephemeral `bitcoind` when available):

```sh
go run ./cmd/praxis bridge
go run ./cmd/praxis bridge --toy
go run ./cmd/praxis bridge --rpc 127.0.0.1:38401 --cookie /path/to/signet/.cookie
```

How the six-step Signet flow works (without trusting anyone to delete a key):
1. **Safety check:** Refuses mainnet ports (`8332`, `8382`) and verifies `getblockchaininfo().chain == "signet"`.
2. **2-of-2 Tapscript vault setup:** Creates two independent live descriptor wallets (`Depositor` and `Claimer`), imports `tr(NUMS, multi_a(2, Depositor, Claimer))` (where `NUMS` is BIP-341's unspendable internal key `50929b74...e803ac0`, forcing all spends through `<Dep> OP_CHECKSIG <Clm> OP_CHECKSIGADD 2 OP_NUMEQUAL`), funds the 2-of-2 `tb1p...` output with `1.00000000 sBTC`, mines 1 Signet block, and has Depositor sign **only** its 1-of-2 partial PSBT (`finalize=false`) paying `0.99998000 sBTC` to Claimer.
3. **Unilateral spend checks (live keys):** Keeps both wallets' private keys live and verifies via `walletprocesspsbt` + `finalizepsbt` that neither Depositor alone (rug-pull attempt) nor Claimer alone (premature withdrawal attempt) can produce a valid 2-of-2 witness (`complete = false`).
4. **Witness encryption (`bqs.BridgeBurn`):** Binds a 132-unknown, 4-constraint, $F_{\max} = 4$ ($\nu = 8$ coset) quadratic commitment system over $\mathbb{F}_q$ to `(vault_outpoint, claimer_address, amount_sats)` and an L2 batch of four burn commitments, encrypts Depositor's 1-of-2 partial PSBT with Praxis, zeroes the plaintext PSBT buffer, and leaves Depositor offline for the rest of the protocol. *(Scope note: in the paper's full instantiation, the BQS encodes a 391,693-wire BN254 Groth16 verifier checking a succinct L2 burn proof; here `bqs.BridgeBurn` encodes the 128-bit burn preimage and batch-slot proof directly so Setup/Enc/Dec run interactively in ~70–230 ms, and demo parameters `Toy`/`Advanced` remain non-cryptographic.)*
5. **Forged-witness check:** Flips one bit of the burn preimage and runs `DecUnchecked`, confirming QAP non-divisibility (`no key found`) and verifying via `gettxout` that the `1.00000000 sBTC` 2-of-2 Signet UTXO remains unspent.
6. **Operator-free co-sign & settlement:** Supplies a valid L2 burn preimage (`DecDetailed`), recovers Depositor's 1-of-2 partial PSBT, co-signs the 2nd BIP-340 Schnorr signature using Claimer's wallet, finalizes the 4-item `OP_CHECKSIGADD` Tapscript witness, broadcasts via `sendrawtransaction`, mines 1 Signet block, and verifies UTXO settlement across peers.

### Command-Line Usage

Run the non-interactive walkthrough in either Toy or Advanced mode:

```sh
go run ./cmd/praxis demo
go run ./cmd/praxis demo --advanced
```

Encrypt a message to a semiprime factoring instance ($n = p \cdot q$ with $p, q < 2^{16}$) and decrypt with its factors:

```sh
go run ./cmd/praxis encrypt factor 3214085717 16 "hello" hello.ct
go run ./cmd/praxis decrypt hello.ct 64283 49999
```

Encrypt to graph $k$-colourability using `--advanced` (chunked powers, FFT QAP, outward sign-class fingerprint search) and decrypt with any valid vertex colouring:

```sh
go run ./cmd/praxis encrypt --advanced colour 0-1,1-2,2-0 3 "hello" hello.ct
go run ./cmd/praxis decrypt hello.ct 0,1,2
```

---

## Specification Coverage: Toy vs. Advanced vs. Paper

The codebase implements **Figures 9 and 10** (Appendix A of ePrint 2026/2971) in two selectable modes so the algebra can be read both in its simplest unchunked/schoolbook form (`praxis.Toy`) and with the structural optimizations of Sections 4.4, 5.1, and 5.2 (`praxis.Advanced`):

| Component | `praxis.Toy` | `praxis.Advanced` | Paper Table 4 ($\lambda = 100$) |
|---|---|---|---|
| **Curve & scalar field $\mathbb{F}_q$** | BN254 ($q \approx 2^{253.6}$) | BN254 ($q \approx 2^{253.6}$) | BN254 ($q \approx 2^{253.6}$) |
| **Ring $R_q = \mathbb{F}_q[Y]/(Y^{d_R}+1)$** | $d_R = 2, \; K = 3$ | $d_R = 4, \; K = 5$ | $d_R = 64, \; K = 71$ |
| **Extension $\mathbb{F}_q[T]/(T^n - c_0)$** | $n = 8 = 2^3, \; c_0 = 5$ | $n = 24 = 3 \cdot 2^3, \; c_0 = 5$ (Serret) | $n = 4{,}608 = 9 \cdot 2^9, \; c_0 = 5$ |
| **Shared-factor grid $K_1 \times 3K_2$** | $2 \times 6 = 12$ cells | $4 \times 9 = 36$ cells | $192 \times 36 = 6{,}912$ cells |
| **Secret integer range $g$** | $2^{20}$ (`1,048,576`) | $2^{24}$ (`16,777,216`) | $\approx 2^{50.6}$ |
| **Quotient / remainder chunks** | $J = 1, \; J' = 1$ (unsplit) | $J = 4, \; J' = 2$ (split, Sec. 5.2) | $J = 11, \; J' = 11$ |
| **Evaluation domain $\mathcal{H}$** | Natural cosets $h^t \mathcal{G}$ + leftovers | Bit-reversed powers in $\mathcal{H}$ (Sec. 4.4) | Bit-reversed powers in $\mathcal{H}$ |
| **QAP & tie polynomial arithmetic** | $O(D^2)$ Lagrange & schoolbook `DivMod` | $O(\lvert\mathcal{H}\rvert \log \lvert\mathcal{H}\rvert)$ radix-2 FFT & Hensel–Newton `DivModFFT` | Radix-2 FFT & binomial division |
| **Centered sampler $\mathcal{D}_g$ (Def. 5.3)** | Exact (`*big.Int`) | Exact (`*big.Int`) | Exact |
| **Target-group search (Fig. 10, Line 9)** | Growing-interval BSGS (`392 B`/baby step) | Outward $\{V, V^{-1}\}$ sign-class search with 64-bit $\mathbb{F}_{p^6}$ fingerprints (`12 B`/baby step) | Outward $\{V, V^{-1}\}$ sign-class search with 64-bit fingerprints + $\mathbb{F}_p$ recurrence |
| **NP statement family** | Hand-built BQS (`factor`, `colour`, `3-SAT`, `BridgeBurn`) | Hand-built BQS (with $0 = 0$ chunk padding) | Universal Groth16 verifier ($N = 391{,}693$) |
| **Ciphertext size (64-bit factoring / full)** | ~129 KB ($N = 64$) | ~237 KB ($N = 64$, $3\times$ more cells) | 7.88 GiB ($N = 391{,}693$) |

---

## Technical Details & Honest Differences from the Paper

### What matches the paper's algebra exactly
1. **Boolean Quadratic Systems & QAP (Definitions 4.1 & 4.6, Lemma 4.7, Equation (4)):** Constraints $\sum_{f \in [F_t]} a_{t,f}(w) b_{t,f}(w) = w_0 c_t(w)$ are encoded with one coset $\mathcal{K}_t$ of order $\nu = 2^{\lfloor \log_2 F_{\max} \rfloor + 1}$ per constraint (avoiding auxiliary R1CS variables for multi-product sums), single points $d_1, \dots, d_N$ for Booleanity ($w_j^2 - w_0 w_j = 0$), $d_0$, and the key point $\rho$. Decryption computes unique quotients $h_{\text{key}}, h_{\text{oth}}$ and an allowed remainder $R_w \in \mathbb{F}_q^{<\nu n_c}[X]$ with zero coefficients at multiples of $\nu$.
2. **Ring Matrix Forms & Extension-Field Weights (Definition 5.1, Section 5.1):** Unknowns are packed $d_R$ at a time into $R_q = \mathbb{F}_q[Y]/(Y^{d_R}+1)$ to form $\varphi_0, \dots, \varphi_{n-1}$ ($\varphi_0(w) = w_0$, $\varphi_1 = \dots = \varphi_{d_R-1} = 0$). For any even $n \mid (q - 1)$, `newField` selects the least $c_0 \ge 2$ that is a non-$p$-th-power for every prime $p \mid n$ (by Serret's theorem, since $4 \mid (q - 1)$ on BN254, this makes $T^n - c_0$ irreducible), sets $\omega = c_0^{(q-1)/n}$ of order $n$ ($\omega^{n/2} = -1$), and computes the $3n/2$ quadratic weights from $U(w) = z(w)\sigma^{n/2-1}(z(w))$ and $V(w) = z(w)\sigma^{n/2}(z(w))$.
3. **Shared-Factor Grid, Tie Masks & Cancellation (Equations (5), (6), (7)):** Left factors $\mathbf{F}_i^{k_1} \in \mathbb{G}_1^2$ and right factors $\mathbf{H}_j^{\text{leg}} \in \mathbb{G}_2^2$ are blinded under the random $2 \times 2$ matrix $\Omega$, with $\varepsilon \in \mathbb{F}_q^* \setminus \{-\omega^{-2k_1}\}$. Decryption computes the three exact tie quotients $x_a^0$ modulo $T^n - c_0$ and five cross polynomials $x_a^\pm$, pairing $\mathbf{Y}_w$ against $\mathbf{B}_w$ to cancel all mask and cross terms identically.
4. **Chunked Powers & Element Counts (Section 5.2, Proposition 5.7(a)):** For arbitrary $J, J' \ge 1$ with $J' \mid n_c$, `Enc` publishes $\Delta = \lceil D/J \rceil$ quotient powers and $(\nu - 1)n_c / J'$ remainder powers in $\mathbb{G}_1$ alongside $(J + J') \cdot \frac{3n}{2}$ cell bases in $\mathbb{G}_2$ (plus $\alpha$-copies). `Public.Counts()` matches Proposition 5.7(a)'s exact formulas:
   $$n_1 = (2K_1 + 1)(N + 1) + \Delta + (\nu - 1)n_c / J', \qquad n_2 = 6K_2(N + 1) + 3K_2 + \tfrac{3n}{2}(J + J') + 13n - 8.$$
5. **Centered Sampler & Sign-Class Fingerprint Search (Definition 5.3, Section 5.2):** `sampleR` draws $r_0 = \lceil N(g+1)/2 \rceil + r_\star - \lfloor \frac{1}{2}\sum_{i=1}^N r_i \rfloor$ so $r(w) - c_w$ has variance $(1 + N/4)(g^2 - 1)/12$ regardless of witness Hamming weight. In `Advanced` mode, `searchOutwardSignFP64` exploits unitary conjugation in BN254's $\mathbb{G}_T$ ($V^{-1} = \overline{V}$, sharing `V.C0` in $\mathbb{F}_{p^6}$) to index $+b$ and $-b$ in one 64-bit fingerprint entry (`uint64` $\to$ `int32`) and step outward from $0$ in shells of width $2\bar{b} - 1$.

### What still differs from the paper (even in `Advanced` mode)
1. **Toy/interactive parameters vs. cryptographic parameters:** Neither `Toy` ($n = 8, g = 2^{20}$) nor `Advanced` ($n = 24, g = 2^{24}$) provides Module-SIS hardness or generic-search security. Running the paper's Table 4 parameters ($n = 4{,}608, g \approx 2^{50.6}, N = 391{,}693$) requires multi-gigabyte precomputation tables (~12.35 GB for Enc, ~5.28 GB for Dec) and produces 7.88 GiB ciphertexts. Note that at tiny $N$ with $n = 24$, `Advanced` ciphertexts are **larger** than `Toy` ciphertexts because the fixed $O(n)$ tie/cross/cell bases ($16n+$ elements in $\mathbb{G}_2$) dominate when $N$ is small; chunking ($J, J' > 1$) only shrinks total size once $D$ and $\nu n_c$ exceed $\frac{3n}{2}$.
2. **No Groth16 verifier circuit or timelock refund leaf (Section 6.1):** Statements are direct BQS encodings (`Factoring`, `Colouring`, `ThreeSAT`, `BridgeBurn`) rather than the paper's 391,693-unknown BQS encoding of a BN254 Groth16 verifier. In the Signet 2-of-2 vault demo (`tr(NUMS, multi_a(2, Depositor, Claimer))`), only the happy-path `OP_CHECKSIGADD` withdrawal leaf is constructed; a production bridge vault would add a `CSV`/`CLTV` timelock refund leaf in the Tapscript tree so funds are recoverable if the claimer never burns on L2.
3. **Giant-step arithmetic & fingerprint table structure (Sections 5.2 & 6.3):** `searchOutwardSignFP64` steps giant candidates via full `bn254.GT` (`E12`) multiplications and verifies fingerprint hits via `GT.Exp`, using fixed 64-bit SplitMix/universal-hash constants in a Go `map`. The paper's Section 6.3 implementation instead advances traces via an XTR-like linear recurrence in $\mathbb{F}_p$ (6 $\mathbb{F}_p$ multiplications + 11 additions per candidate), uses per-run random linear forms for fingerprints, and stores a sorted flat `(uint64, uint32)` array with a directory.
4. **Subproduct-tree & Newton FFTs vs. binomial decomposition (Proposition 5.7 proof):** In `Advanced` mode, `Setup` builds vanishing polynomials with a binary subproduct tree of FFT multiplications ($O(D \log^2 D)$) and `Dec` divides polynomials via Hensel/Newton power-series inversion (`DivModFFT`, $O(D \log D)$), rather than decomposing prefix vanishing polynomials into $O(\log D)$ sparse binomials $X^{2^b} - c$. Likewise, `forms()` expands the ring matrix into dense vectors ($O(n N)$) rather than multiplying in $R_q$ via NTTs.
5. **Standard point compression & in-memory serialization (Section 6.3):** `marshal.go` writes standard `gnark-crypto` compressed `G1Affine` (32 B), compressed `G2Affine` (64 B), and uncompressed `GT` (384 B) slices in memory (verifying curve and prime-order subgroup membership on read, including $z \ne 0 \land z^q = 1$ for $\mathbf{K}^\alpha \in \mathbb{G}_T$). It does not implement Koshelev's 766-bit batch compression or single-pass disk streaming.
6. **Random-oracle domain separation & validation boundaries:**
   - `H_seed` expands a 32-byte seed with SHA-512 per $R_q$ coefficient (`"praxis-demo/seed" || seed || i || j || s`, reduced mod $q$, bias $< 2^{-258}$); `H_key` expands `[kappa]_T` with SHA-256 in counter mode (`"praxis-demo/key" || ctr || kb`) to mask arbitrary-length `[]byte` messages rather than fixed $\mu$-bit strings.
   - `bqs.System.Validate()` requires at least one constraint ($n_c \ge 1$, whereas Section 5.2 allows $n_c = 0$).
   - `Dec` checks `pp.S.IsWitness(w)` before running Figure 10's algebra; `DecUnchecked` runs Figure 10 directly without checking `IsWitness` first.

---

## Verification & Test Suite

Run all static checks and tests (including `-race`):

```sh
go vet ./...
go test -race ./...
```

What the test suite checks across all seven packages:
1. **Algebraic conformance (`praxis`):** Direct verification of Definition 4.6 evaluation-point admissibility, Lemma 4.7 QAP quotient/remainder exactness on witnesses vs. 1-bit flips, Serret extension irreducibility ($\text{ord}(\omega) = n, \; \omega^{n/2} = -1$), Equation (6) exact tie divisions by $T^n - c_0$, Equation (7)'s mask identity in $\mathbb{F}_q$, Lemma 5.5 search-offset bounds under $\mathcal{D}_g$, and Proposition 5.7(a) element counts (both unchunked and chunked).
2. **Varied BQS shapes & parameter grids (`praxis`, `bqs`):** Random planted-witness systems from $N = 0$ to $N = 200$ unknowns, coset sizes $\nu \in \{2, 4, 8, 16, 32\}$, zero right-hand sides, unconstrained unknowns, multiple distinct witnesses of unequal Hamming weight unlocking the same ciphertext, all 29 valid small power-of-two `Params` combinations ($n \in \{4, 8, 16\}$, $d_R = 1 \dots 8$, $g = 1$, extreme $K_1 = 1$ and $K_2 = 1$), plus non-power-of-two `Advanced` mode ($n = 24, J = 4, J' = 2$).
3. **Arithmetic & boundary regressions (`poly`, `praxis`):** Degenerate polynomials (`nil`, untrimmed zeros, constants, divisor longer than dividend), FFT vs. schoolbook cross-checks (`MulFFT`, `FromRootsFFT`, `DivModFFT`), exact subgroup-filling systems ($D = |\mathcal{H}|$), empty and 100 KB messages, and `*big.Int` overflow regressions up to $G = 2^{40}$ and $N \sim 2^{27}$.
4. **Malformed ciphertexts & CLI inputs (`praxis`, `cmd/praxis`, `tui`):** Truncated streams, oversized length headers (verifying bounded streaming allocation), cross-system ciphertexts of both different and identical shapes, off-curve $\mathbb{G}_1 / \mathbb{G}_2$ coordinates, twist points outside the prime-order $\mathbb{G}_2$ subgroup, elements in $\mathbb{F}_{p^{12}} \setminus \mathbb{G}_T$ (`Ka = 0`, `Ka = 2`), CLI error exit codes, and end-to-end Bubble Tea v2 TUI state transitions.
5. **2-of-2 Bitcoin Private Signet bridge (`bqs`, `signet`):** Mainnet port & non-loopback RPC rejection, BIP-380 descriptor checksum vectors, `BridgeBurn` preimage/slot soundness and `(outpoint, recipient, amount)` context-replay resistance, live-key unilateral spend failure for both Depositor and Claimer, forged-witness `DecUnchecked` rejection with on-chain `gettxout` verification, and full 4-item `OP_CHECKSIGADD` Tapscript settlement on an isolated ephemeral `signetchallenge=51` `bitcoind`.

---

## Repository Layout

| Path | Contents |
|---|---|
| [`bqs/`](bqs/) | Boolean quadratic systems (`System`, `PadConstraints`), validation, and four NP encodings: `Factoring`, `Colouring`, `ThreeSAT`, and `BridgeBurn` |
| [`signet/`](signet/) | Loopback-guarded Bitcoin Private Signet (`signetchallenge=51`) RPC client, ephemeral `bitcoind` test harness, and 2-of-2 Tapscript (`OP_CHECKSIGADD`) PSBT vault engine |
| [`poly/`](poly/) | Schoolbook (`poly.go`) and radix-2 FFT / subproduct-tree / Hensel–Newton (`fft.go`) polynomial arithmetic over BN254's $\mathbb{F}_q$ |
| [`praxis/params.go`](praxis/params.go) | `Params`, `Toy` & `Advanced` presets, parameter validation, and Serret extension field $\mathbb{F}_q[T]/(T^n - c_0)$ |
| [`praxis/setup.go`](praxis/setup.go) | QAP construction, natural & bit-reversed subgroup $\mathcal{H}$ placement, and FFT prefix interpolation (Definition 4.6, Lemma 4.7, Section 4.4) |
| [`praxis/forms.go`](praxis/forms.go) | Seeded ring matrix $M \in R_q^{K \times (\ell+1)}$, linear forms, quadratic weights $U, V$, and the $K_1 \times 3K_2$ grid (Definition 5.1, Section 5.1) |
| [`praxis/enc.go`](praxis/enc.go) | Setup layout, centered sampler $\mathcal{D}_g$, tie masks, chunked powers, and encryption (Figure 9, Proposition 5.7) |
| [`praxis/dec.go`](praxis/dec.go) | Decryption, `DecUnchecked`, cancellation polynomials, pairings, and growing-interval BSGS (Figure 10) |
| [`praxis/search_fast.go`](praxis/search_fast.go) | Section 5.2 outward discrete-log search on $\mathbb{G}_T$ sign classes $\{V, V^{-1}\}$ with 64-bit $\mathbb{F}_{p^6}$ fingerprints and telemetry |
| [`praxis/marshal.go`](praxis/marshal.go) | Compressed binary serialization with curve and $\mathbb{G}_1 / \mathbb{G}_2 / \mathbb{G}_T$ subgroup validation |
| [`tui/`](tui/) | SilkCircuit-styled Charm (`bubbletea/v2` + `lipgloss/v2`) interactive workbench |
| [`cmd/praxis/`](cmd/praxis/) | CLI entrypoint (`tui`, `bridge`, `demo`, `encrypt`, `decrypt`) |
| [`curve/`](curve/) | Sanity checks on BN254 generators, bilinearity, and 254-bit prime order |
| [`docs/demo.tape`](docs/demo.tape), [`docs/demo.gif`](docs/demo.gif) | VHS script and recorded GIF of the interactive workbench |
