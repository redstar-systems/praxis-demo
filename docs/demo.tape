# Records docs/demo.gif. Run from the repository root:  vhs docs/demo.tape

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1480
Set Height 900
Set Padding 20
Set Framerate 24
Set TypingSpeed 35ms
Set Theme {"background":"#12101a","foreground":"#f8f8f2","cursor":"#e135ff"}

# Build the tool out of sight and put it on PATH.
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

# 4. Operator-Free 2-of-2 Bitcoin Private Signet Taproot Bridge Vault:
#    [e] Fund 2-of-2 tr(NUMS, multi_a(2, Dep, Clm)) vault (both keys LIVE), seal 1/2 PSBT
#    [x] Attack with forged burn proof (QAP fails, 2-of-2 Signet UTXO verified unspent)
#    [d] Prove valid L2 burn -> decrypt 1/2 PSBT -> Claimer co-sign & mine on Signet
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
