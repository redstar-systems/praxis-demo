# Records docs/demo.gif. Run from the repository root:  vhs docs/demo.tape

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1520
Set Height 940
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
Wait+Screen@10s /PARAMETER SPECTRUM/
Sleep 1.2s

# 1. Slide up to Tier 3 (n=96, g=2^32), toggle [p] so Theorem 5.9 (P1) & MSIS turn green, and decrypt!
Type "]"
Sleep 700ms
Type "p"
Sleep 1s
Type "d"
Wait+Screen@15s /UNLOCKED:/
Sleep 1.8s
Type "p"
Sleep 600ms

# 2. Slide up to Tier 4 (n=384, g=2^40) -> Tier 6 (Table 4: n=4608, g~2^50.6), preview & cycle palette, then sweep Tiers 1..4!
Type "]"
Sleep 600ms
Type "]"
Sleep 600ms
Type "]"
Sleep 1.4s
Type "v"
Sleep 900ms
Type "v"
Sleep 700ms
Type "v"
Sleep 700ms
Type "v"
Sleep 700ms

# Step back to Tier 2, select 3-SAT, and run 4-tier Spectrum Sweep [c] (n=8 -> 384, g=2^20 -> 2^40).
Type "["
Sleep 300ms
Type "["
Sleep 300ms
Type "["
Sleep 300ms
Type "["
Sleep 500ms
Type "3"
Sleep 600ms
Type "c"
Wait+Screen@20s /SPECTRUM SWEEP/
Sleep 2.5s

# 3. Operator-Free 2-of-2 Bitcoin Private Signet Taproot Bridge Vault.
Type "4"
Sleep 800ms
Type "e"
Wait+Screen@60s /BOTH KEYS LIVE/
Sleep 2s
Type "x"
Wait+Screen@15s /still UNSPENT on Signet/
Sleep 2.2s
Type "d"
Wait+Screen@60s /SWEPT ON SIGNET:/
Sleep 3.2s

Type "q"
Sleep 600ms

Hide
Type@0ms "rm -rf $PRAXIS_BIN"
Enter
