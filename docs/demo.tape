# Records docs/demo.gif. Run from the repository root:  vhs docs/demo.tape

Output docs/demo.gif

Set Shell bash
Set FontSize 18
Set Width 1280
Set Height 720
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

# Build the tool out of sight and put it on the path.
Hide
Type "export PRAXIS_BIN=$(mktemp -d) && go build -o $PRAXIS_BIN/praxis ./cmd/praxis && export PATH=$PRAXIS_BIN:$PATH && cd $PRAXIS_BIN && export PS1='$ ' && clear"
Enter
Sleep 4s
Show

Type "# Witness encryption: lock a message to a puzzle, not to a key."
Enter
Sleep 1.5s
Type "# Lock it to a number. Whoever knows the factors can read it."
Enter
Sleep 1s
Type 'praxis encrypt factor 3214085717 16 "meet at the old pier" note.ct'
Enter
Sleep 3s

Type "# Wrong factors get nothing."
Enter
Sleep 500ms
Type "praxis decrypt note.ct 64283 49998"
Enter
Sleep 3s

Type "# The right ones open it. No key was ever made."
Enter
Sleep 500ms
Type "praxis decrypt note.ct 64283 49999"
Enter
Sleep 4s

Type "clear"
Enter
Type "# Or lock it to a graph: whoever can colour it can read it."
Enter
Sleep 1s
Type 'praxis encrypt colour 0-1,1-2,2-0,2-3,3-0 3 "any valid colouring works" graph.ct'
Enter
Sleep 3s
Type "praxis decrypt graph.ct 0,1,2,1"
Enter
Sleep 2.5s
Type "praxis decrypt graph.ct 2,0,1,0"
Enter
Sleep 3s
Type "# Demonstration parameters. Not secure."
Enter
Sleep 3s

Hide
Type "cd / && rm -rf $PRAXIS_BIN"
Enter
