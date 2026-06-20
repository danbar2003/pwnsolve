"""Global, per-user configuration for the remote debug box.

Set once (``~/.config/pwnsolve/config.toml``) and reused by every challenge.
"""
import os
import tomllib
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "pwnsolve"
CONFIG_PATH = CONFIG_DIR / "config.toml"

# Sensible starting point; edit via `solveconfig --edit`.
DEFAULTS = {
    "ssh": {
        "host": "127.0.0.1",
        "user": "user",
        "port": 22,
        "key": "~/.ssh/id_ed25519",
        # Each challenge is synced under here as <remote_base>/<challenge-name>.
        # A tmp dir keeps the box tidy and leaks no home-directory paths.
        "remote_base": "/tmp/pwnsolve",
    },
    "debug": {
        "gdb_port": 31337,
        "debugger": "pwndbg",     # pwndbg | gdb | gef | /path/to/debugger
        "terminal": "auto",       # auto | tmux | iterm | terminal | <terminal program>
        # Fetch real glibc debug symbols by build-id (gives main_arena, hooks,
        # heap structs). Needs network on first use; cached afterwards. Turn
        # "off" only if the box's libc isn't on a debuginfod server / no network.
        "debuginfod": "on",
    },
}

_TEMPLATE = """\
# pwnsolve configuration — the remote Linux box where target binaries run + are debugged.

[ssh]
host = "{host}"
user = "{user}"
port = {port}
key  = "{key}"
# Challenges are synced under here as <remote_base>/<challenge-name>.
remote_base = "{remote_base}"

[debug]
gdb_port = {gdb_port}      # gdbserver port (forwarded to 127.0.0.1 on this machine)
debugger = "{debugger}"    # pwndbg | gdb | gef | /path/to/debugger
terminal = "{terminal}"    # auto | tmux | iterm | terminal | <terminal program>
debuginfod = "{debuginfod}"  # on => fetch real glibc symbols by build-id (cached); off => no network
"""


def _merge(base, override):
    out = {k: dict(v) for k, v in base.items()}
    for section, vals in (override or {}).items():
        out.setdefault(section, {}).update(vals)
    return out


def ensure_config():
    """Create the config file with defaults if it does not exist. Returns its path."""
    if not CONFIG_PATH.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        flat = {**DEFAULTS["ssh"], **DEFAULTS["debug"]}
        CONFIG_PATH.write_text(_TEMPLATE.format(**flat))
    return CONFIG_PATH


def load_config():
    """Load config merged over defaults (creating the file on first use)."""
    ensure_config()
    with open(CONFIG_PATH, "rb") as f:
        data = tomllib.load(f)
    return _merge(DEFAULTS, data)
