# Records docs/demo.gif. Run from the repository root:  vhs docs/demo.tape

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1480
Set Height 820
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
Sleep 2s

# 1. Semiprime Factoring (R1CS) in Advanced Mode: encrypt & unlock with (p, q).
Type "e"
Sleep 1.5s
Type "d"
Sleep 2.5s

# 2. Petersen Graph 3-Colouring (nu=4 cosets): unlock with w1, alternate w2, then tamper x.
Type "2"
Sleep 1s
Type "d"
Sleep 2.2s
Type "w"
Sleep 2.5s
Type "x"
Sleep 2.5s

# 3. 3-SAT Gate Circuit: live side-by-side Toy vs Advanced benchmark, and toggle modes.
Type "3"
Sleep 1s
Type "c"
Sleep 3s

Tab
Sleep 1.5s
Tab
Sleep 2s

Type "q"
Sleep 800ms

Hide
Type@0ms "rm -rf $PRAXIS_BIN"
Enter
