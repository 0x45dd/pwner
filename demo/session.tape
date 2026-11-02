# VHS tape for the README demo — a real agentic session against the local demo target.
#
#   python demo/target.py &        # the thing being scanned (binds 127.0.0.1 only)
#   vhs demo/session.tape
#
# The API key is read from ~/.config/pwner/config.json, so it never appears on screen.
# This drives a live model, so every render differs and costs a few cents. Waits are on
# screen content rather than fixed sleeps, so a slower run does not desync the recording.

Output demo/session.gif

Set Shell "bash"
Set FontSize 13
Set Width 1180
Set Height 700
Set Padding 18
Set Framerate 10
Set TypingSpeed 45ms
Set WindowBar Colorful
Set BorderRadius 8
Set Theme "Catppuccin Mocha"
Set WaitTimeout 300s

# Setup is hidden: activate the venv and give bash a short prompt, so the recording
# starts on a clean line instead of "((.venv) ) >".
Hide
Type "cd /Users/berk/localagent/pwner && source .venv/bin/activate"
Enter
Type "export VIRTUAL_ENV_DISABLE_PROMPT=1 PS1='$ ' && clear"
Enter
Sleep 1500ms
Show

Type "pwner chat 127.0.0.1 --max-steps 12"
Sleep 500ms
Enter

# Wait for the session banner rather than guessing how long startup takes.
Wait+Screen /mode: agent|talk to the agent|❯/
Sleep 1500ms

Type "the web service on 8080 is the target — get authenticated access"
Sleep 400ms
Enter

# The agent works: port scan, fingerprint, read the login page, spot the
# "password is the serial number" hint, pull /api/status, log in.
#
# Waiting on the status bar, not on the log: the log scrolls, so a finding can leave the
# screen before the wait next polls for it. The bar is empty until the first turn spends
# tokens and then reads "ready · <cost> this session", which makes it an exact
# turn-finished signal — the header's own "... · ready" never matches this pattern.
Wait+Screen /ready ·/
Sleep 3s

Type "/findings"
Sleep 300ms
Enter
Sleep 6s

Type "/exit"
Sleep 300ms
Enter
Sleep 1500ms
