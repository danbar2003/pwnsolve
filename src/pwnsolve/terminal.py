"""Open a command in a new terminal pane/window, portably.

Order of preference: tmux split -> (macOS) iTerm split / Terminal.app
-> (Linux) $TERMINAL / x-terminal-emulator / gnome-terminal / konsole / xterm.
"""
import os
import sys
import shutil
import tempfile
import subprocess


def _wrap(cmd):
    """Write a tiny launcher that runs ``cmd`` then drops to a shell (pane stays open)."""
    f = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
    f.write("#!/bin/bash\n%s\necho; echo '[ debugger session ended ]'; exec $SHELL\n" % cmd)
    f.flush(); f.close()
    os.chmod(f.name, 0o755)
    return f.name


def _iterm_available():
    return os.path.exists("/Applications/iTerm.app") or \
        os.environ.get("TERM_PROGRAM") == "iTerm.app"


def _iterm_split(script):
    osa = '''
tell application "iTerm"
    activate
    if (count of windows) = 0 then
        create window with default profile
        tell current session of current window to write text "bash %s"
    else
        tell current session of current window
            set newSession to (split vertically with default profile)
        end tell
        tell newSession to write text "bash %s"
    end if
end tell
''' % (script, script)
    subprocess.Popen(["osascript", "-e", osa])


def _terminal_app(script):
    subprocess.Popen([
        "osascript",
        "-e", 'tell application "Terminal" to do script "bash %s"' % script,
        "-e", 'tell application "Terminal" to activate',
    ])


def launch(cmd, prefer="auto"):
    prefer = (prefer or "auto").lower()

    if prefer in ("auto", "tmux") and os.environ.get("TMUX") and shutil.which("tmux"):
        subprocess.Popen(["tmux", "split-window", "-h", cmd])
        return True

    script = _wrap(cmd)

    if sys.platform == "darwin":
        if prefer in ("auto", "iterm") and _iterm_available():
            _iterm_split(script)
            return True
        _terminal_app(script)
        return True

    # Linux / other: try a sequence of terminal emulators.
    candidates = []
    if prefer not in ("auto", "tmux", "iterm", "terminal"):
        candidates.append((prefer, ["-e"]))      # explicit terminal program
    candidates += [
        (os.environ.get("TERMINAL"), ["-e"]),
        ("x-terminal-emulator", ["-e"]),
        ("gnome-terminal", ["--"]),
        ("konsole", ["-e"]),
        ("xfce4-terminal", ["-e"]),
        ("xterm", ["-e"]),
    ]
    for term, term_args in candidates:
        if term and shutil.which(term):
            subprocess.Popen([shutil.which(term), *term_args, "bash", script])
            return True

    # Nothing worked — tell the user how to attach by hand.
    print("[pwnsolve] No terminal found. Run the debugger manually:\n    bash %s" % script)
    return False
