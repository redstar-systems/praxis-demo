# `praxis-lean` Conformance Mapping

This document maps the runnable Go implementation in `praxis-demo` directly to the authors' Lean 4 formalization in [`psivesely/praxis-lean`](https://github.com/psivesely/praxis-lean) (*"Praxis: Practical Witness Encryption for NP"*, Tse, Vanjani, and Vesely, IACR ePrint 2026/2971).

Every equivalence listed below is checked automatically in [`praxis/lean_conformance_test.go`](../praxis/lean_conformance_test.go) (`go test -v -run "TestLean|TestSignClassKDF" ./praxis`) by instantiating Lean's `Setting.lean` scalar test model (`expGroups = Additive F_q`, where `pair a b = a * b`) alongside BN254 group operations.

---

## 1. Constants & Instantiation Parameters (`Praxis/Constants.lean`)

| `Praxis/Constants.lean` | Go Symbol (`praxis`) | Verified Value |
|---|---|---|
| `q` | `fr.Modulus()` | `21888242871839275222246405745257275088548364400416034343698204186575808495617` |
| `n`, `m` | `Table4.NForms()`, `n/2` | `4608`, `2304` |
| `c0` | `newField(4608).c0` | `5` (least non-2nd, non-3rd power in $\mathbb{F}_q^*$) |
| `beta` | `newField(4608).omega` | `15455056031545522072329890326622223210121953105925913337013641664433101999706` ($= 5^{(q-1)/4608} \bmod q$, $\beta^{2304} \equiv -1$) |
| `ring_degree`, `module_rows` | `Table4.DR`, `Table4.K` | `64`, `71` ($n = (71+1) \cdot 64 = 4608$) |
| `K1`, `K2` | `Table4.K1`, `Table4.K2` | `192`, `12` ($K_1 K_2 = 2304 = n/2$, `Cells() = 6912`) |
| `M_q`, `W_r` | `Table4.J`, `Table4.JPrime` | `11`, `11` |
| `g_bits` | `Table4G` (`spectrum.go`) | `1_736_375_024_658_487` (`51` bits, least $g$ with $g^8 \ge 2^{405}$) |

---

## 2. Module-by-Module Symbol Correspondence

| Lean 4 File & Definition | Go Counterpart | Conformance Check |
|---|---|---|
| `Praxis/Forms.lean`: `rqMul`, `slotPoly`, `phi`, `formVec` | `Params.forms`, `ringElement` (`praxis/forms.go`) | Exact $\mathbb{F}_q$ matrix equality across all $n \times (N+1)$ entries: form `0` is $x_0$, forms `1..d_R-1` are $0$, `(row, none)` maps to `ringElement(seed, row+1, 0, d_R)`, and `(row, some j)` wraps negacyclically mod $Y^{d_R}+1$. |
| `Praxis/Kummer.lean`: `KummerPoly`, `BetaLaws`, `sigma`, `kmul`, `Uw`, `Vw` | `newField`, `field.reduce`, `Params.weightsOf` (`praxis/params.go`, `forms.go`) | Since $\beta^m = -1$ ($m = n/2$), Lean's $\beta^{m-1} = -\beta^{-1}$ equals Go's `cMinus = -1/omega`. `Uw` equals `wt.U`, and `Vw(j)` equals `wt.V[2*j]` (odd entries of `wt.V` vanish identically). |
| `Praxis/Grid.lean`: `LegKind` (`E, O, V`), `legExp`, `cellExp`, `IsKeyCell`, `cellWeight`, `wKey` | `kindE/kindO/kindV`, `legExp`, `cell`, `xi` (`praxis/forms.go`) | Identical leg ordering (`E` $0..K_2-1$, `O` $0..K_2-1$, `V` $0..K_2-1$), identical key cell `(0, (E, 0))` $\leftrightarrow$ `cell == 0`, and identical `xi(wt, k1, leg)` across all $3 K_1 K_2$ cells. |
| `Praxis/Enc.lean`: `piAt`, `legScaleAt`, `gamma`, `legMask`, `H1`, `H2`, `r1Exp`, `r2Exp`, `g1Exp`, `g2Exp`, `gtExp`, `kappa` | `Public.computeEncScalars`, `EncDetailed` (`praxis/enc.go`) | Exact $\mathbb{F}_q$ equality on every $\mathbb{G}_1$ coordinate (`L1`, `L2`, `GY`, `QP`, `RP`), every $\mathbb{G}_2$ coordinate (`ZeroCoordinate`, `R2`, `SC`, `QB`, `RB`, `GM`, `GB` across `.plain` and `.alpha`), `kappa`, and `alpha * kappa`. |
| `Praxis/Dec.lean`: `tieQuot`, `crossPoly`, `evalComb`, `psi`, `findT`, `decRef` | `dec`, `centerBig`, `searchBigWithStats`, `searchOutwardSignFP64` (`praxis/dec.go`, `search_fast.go`) | Exact $\mathbb{F}_q$ equality between Lean's cell-summed `crossPoly` (`.c1eps`, `.c2eps`, `.c2div`, `.c3eps`, `.c3div`) and Go's polynomial `xc`, plus exact recovery of `H' = (r(w) - c(w)) * Psi1` and `K == kappa` in `expGroups`. |
| `Praxis/Keys.lean`: `ClassName := Sym2 Label`, `labelName`, `maskMsg` | `Params.SignClassKDF`, `keyPadFor` (`praxis/enc.go`) | When `SignClassKDF: true`, derives the message pad from `V.C0` in $\mathbb{F}_{p^6}$, which is invariant under unitary inversion $V \leftrightarrow V^{-1} = \overline{V}$ in BN254's $\mathbb{G}_T$. |

---

## 3. Documented Differences Between `praxis-lean` and Appendix A of the Paper

As noted in [`psivesely/praxis-lean`'s `README.md`](https://github.com/psivesely/praxis-lean), the Lean formalization differs in two intentional places from Appendix A (Figures 9 and 10) of ePrint 2026/2971:

1. **Extra auxiliary sum elements `totL1`, `totL2`, `totR1`, `totR2` in `Praxis/Published.lean`:**
   - `Praxis/Published.lean` adds `totL1 (k1)` and `totL2 (k1)` (`2 * K1` elements in $\mathbb{G}_1$, holding $\sum_i L_{1,i}$ and $\sum_i L_{2,i}$) and `totR1 (σ, leg)` and `totR2 (σ, leg)` (`2 * 3 * K2 = 6 * K2` elements per sector $= 12 * K2$ elements in $\mathbb{G}_2$) to streamline the generic-group extractability reduction (`Bridge.lean` / `Extract.lean`).
   - Neither `Praxis/Dec.lean` (`evalComb`) nor Figure 10 of the paper reads those total-sum elements during decryption.
   - `Public.Counts()` and `Public.PaperCounts()` match **Proposition 5.7(a)** of the paper; `Public.LeanCounts()` adds `(2*K1, 12*K2)` and is verified against `Published.lean`'s `countG1` and `countG2` in `TestLeanConstantsConformance`.
2. **Sign-class key derivation (`Praxis/Keys.lean` vs. Appendix A):**
   - Appendix A masks the message with $H_{\text{key}}([\kappa]_T)$, whereas Section 6.4 and `Praxis/Keys.lean` mask the message with `kdf(name([\kappa]_T))` on the unordered inverse pair $\{V, V^{-1}\}$ (`Sym2 Label`).
   - `praxis.Params` supports both: default `SignClassKDF: false` follows Appendix A (`key.Bytes()`), while `SignClassKDF: true` hashes `gtC0Bytes(key)` (the 192-byte $\mathbb{F}_{p^6}$ `C0` coordinate canonical for $\{V, V^{-1}\}$ on BN254) as tested in `TestSignClassKDFInvarianceAndRoundTrip`.
