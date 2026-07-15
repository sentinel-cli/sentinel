# VHS Tape Script for Crenox Demo
# Run: vhs < demo.tape to generate demo.gif
# --------------------------------------------------

Output docs/demo.gif

# Terminal Settings
Set Shell "bash"
Set FontSize 15
Set FontFamily "JetBrains Mono"
Set Width 1200
Set Height 620
Set Padding 20
Set Theme "Catppuccin Mocha"

# 1. Initialize a new repo and install Crenox
Type "mkdir -p crenox-demo && cd crenox-demo && git init"
Enter
Sleep 1s
Type "git config user.name 'Crenox Demo' && git config user.email 'demo@crenox.dev'"
Enter
Sleep 1s
Ctrl+L
Sleep 1s

Type "crenox install"
Enter
Sleep 2s
Ctrl+L
Sleep 1s

# 2. Stage a safe file and commit it
Type "echo 'def hello(): print(hello)' > app.py"
Enter
Sleep 1s
Type "git add app.py"
Enter
Sleep 1s
Type "git commit -m 'Initial commit'"
Enter
Sleep 3.5s
Ctrl+L
Sleep 1s

# 3. Add an AWS Secret and attempt to commit (should block)
Type "echo 'AWS_KEY = AKIAIOSFODNN7EXAMPLE' > config.py"
Enter
Sleep 1s
Type "git add config.py"
Enter
Sleep 1s
Type "git commit -m 'Configure AWS credentials'"
Enter
Sleep 6s
Ctrl+L
Sleep 1s

# 4. Use inline suppression to bypass the block
Type "echo 'AWS_KEY = AKIAIOSFODNN7EXAMPLE # crenox:ignore' > config.py"
Enter
Sleep 1.5s
Type "git add config.py"
Enter
Sleep 1s
Type "git commit -m 'Configure AWS credentials (suppressed)'"
Enter
Sleep 4.5s

# 5. Show clean status and exit
Type "git log --oneline"
Enter
Sleep 2.5s
Type "cd .. && rm -rf crenox-demo"
Enter
Sleep 1.5s
