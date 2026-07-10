# VHS tape for the ai-assistant demo GIF (https://github.com/charmbracelet/vhs)
# Prereqs: the stack is up and seeded (make keys wazuh securityconfig poc seed),
# and you run vhs from integrations/ai-assistant/.
#   vhs demo/demo.tape
# Output lands at demo/demo.gif - reference it from the top of README.md.

Output demo/demo.gif

Set FontSize 15
Set Width 1400
Set Height 800
Set Padding 16
Set TypingSpeed 30ms

Type "./demo/demo.sh"
Enter

# Steps 1-3 are fast (auth + direct indexer probes)
Sleep 12s

# Step 4 runs a real model turn - give it room to finish
Sleep 45s

# Step 5 zero-hit diagnosis turn
Sleep 40s

Sleep 5s
