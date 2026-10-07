# ProofTrace — self-recording 90s demo.
#   vhs demo/demo.tape   ->   demo/prooftrace.gif (+ .mp4)
# Deterministic: stub investigator + subprocess sandbox, fixed pacing, so the
# recording is pixel-identical every run and never stalls.

Output demo/prooftrace.gif
Output demo/prooftrace.mp4

Set Shell "bash"
Set FontSize 13
Set Width 1360
Set Height 860
Set Padding 14
Set TypingSpeed 35ms
Set Theme "Dracula"

Hide
Type "cd /Users/surya/Ayrus" Enter
Type "clear" Enter
Show

Type "make demo-record"
Sleep 800ms
Enter

# the run paces itself to ~65s; hold on the final card to the end
Sleep 75s
