Output docs/demo.gif

# Records the README demo: pi starts in a clean scratch workspace,
# /vet evaluates an update candidate and prints the full report.
# Prerequisite (once): /Volumes/RamDisk/pi-vetter-demo exists as a git repo
# with a package.json, and the pi-vetter scan cache is warm for
# @narumitw/pi-statusline (run /vet on it once before recording).

Require pi

Set Shell "zsh"
Set FontFamily "JetBrainsMono Nerd Font"
Set FontSize 16
Set Width 1200
Set Height 1060
Set Margin 16
Set MarginFill "#181825"
Set BorderRadius 10
Set WindowBar Colorful

Hide
Type "cd /Volumes/RamDisk/pi-vetter-demo"
Enter
Sleep 500ms
Type "pi"
Enter
Sleep 45s
Show
Sleep 1s

Type@80ms "/vet npm:@narumitw/pi-statusline"
Sleep 500ms
Enter
Sleep 1500ms

Hide
Sleep 45s
Show
Sleep 4s
Screenshot docs/demo.png

Hide
Ctrl+C
Sleep 500ms
Ctrl+C
Sleep 500ms
