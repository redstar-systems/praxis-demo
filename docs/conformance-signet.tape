# Records docs/conformance-signet.gif (v0.2.0: praxis-lean conformance + two-leaf 2-of-2/CSV Signet vault).
# Run from the repository root:  vhs docs/conformance-signet.tape

Output docs/conformance-signet.gif

Set Shell "bash"
Set FontSize 16
Set Width 1520
Set Height 940
Set Padding 20
Set Framerate 24
Set TypingSpeed 32ms
Set Theme {"background":"#12101a","foreground":"#f8f8f2","cursor":"#e135ff"}

# Pre-build binary and warm test cache out of sight so live execution is crisp.
Hide
Type@0ms "export PRAXIS_BIN=$(mktemp -d) && go build -o $PRAXIS_BIN/praxis ./cmd/praxis && go test -run=^$ ./praxis >/dev/null && export PATH=$PRAXIS_BIN:$PATH && export PS1='$ ' && clear"
Enter
Sleep 4s
Show

# 1. Verify symbol-for-symbol F_q exponent & constant conformance against psivesely/praxis-lean.
Type "go test -count=1 -v -run 'TestLean|TestSignClassKDF' ./praxis"
Enter
Wait+Screen@15s /praxis-demo\/praxis/
Sleep 2.6s

# 2. Run the CLI two-leaf (2-of-2 + OP_CSV) Bitcoin Private Signet vault audit with (P1)/MSIS padding.
Type "praxis bridge --admissible"
Enter
Wait+Screen@60s /Final Balances:/
Sleep 3.2s

# 3. Open the SilkCircuit TUI on Tab 4 to inspect the live two-leaf Tapscript & CSV(6) mempool guard.
Type "praxis tui"
Enter
Wait+Screen@10s /PARAMETER SPECTRUM/
Sleep 800ms
Type "4"
Sleep 900ms
Type "p"
Sleep 800ms
Type "e"
Wait+Screen@60s /non-BIP68-final/
Sleep 2.2s
Type "x"
Wait+Screen@15s /still UNSPENT on Signet/
Sleep 2s
Type "d"
Wait+Screen@60s /SWEPT ON SIGNET:/
Sleep 3.2s

Type "q"
Sleep 600ms

Hide
Type@0ms "rm -rf $PRAXIS_BIN"
Enter
