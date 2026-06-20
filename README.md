# pwnsolve

Write and run pwntools solve scripts **locally** (e.g. on an Apple-Silicon Mac)
while the target Linux binary runs — and is debugged with **pwndbg/gdb** — on a
remote Linux box via `gdbserver`. Only the binary ever executes remotely.

How it works: a single `ssh -T -L <port>` invocation runs `gdbserver` on the box.
gdbserver inherits the binary's stdin/stdout, so pwntools drives the process I/O
straight through that ssh pipe, while the same ssh forwards the gdbserver port to
`127.0.0.1` where your local debugger attaches.

## Install

```bash
pip install -e .          # into your pwntools venv
```

## Configure the box once

`pip install` does **not** create a config file. It is created lazily, with
placeholder defaults, the first time you run any `solve*` command (or a
`solve.py`). So the first thing to do on a fresh install is point it at your box:

```bash
solveconfig --edit        # creates ~/.config/pwnsolve/config.toml (if needed), opens $EDITOR
```

The placeholder defaults (`host = "127.0.0.1"`, `user = "user"`) won't connect
anywhere real — edit `[ssh]` to your VM/server before running a challenge.
Honors `$XDG_CONFIG_HOME` (otherwise `~/.config`).

```toml
[ssh]
host = "your.box.example"
user = "user"
port = 22
key  = "~/.ssh/id_ed25519"
remote_base = "/tmp/pwnsolve"

[debug]
gdb_port = 31337
debugger = "pwndbg"       # pwndbg | gdb | gef | /path/to/debugger
terminal = "auto"         # auto | tmux | iterm | terminal | <terminal program>
debuginfod = "on"         # on => fetch real glibc symbols by build-id (cached); off => no network
```

## Per challenge

```bash
cd ~/ctf/some_challenge
solveinit                 # patch on host (pwninit), write solve.py, push binary+libs
#   solveinit --no-patch  # use an existing patched binary as-is
#   solveinit --host 1.2.3.4 --port 31337

python3 solve.py LOCAL    # run on the box, drive I/O locally (no debugger)
python3 solve.py GDB      # debug via gdbserver, local pwndbg attaches
python3 solve.py          # connect to the real CTF server

solvesync                 # re-push binary+libs after re-patching
```

Patching happens on the **host** (pwninit/patchelf), and only the **runtime
files** — the patched binary plus its loader/libc (`ld-*.so`, `libc-*.so`,
`libc.so.6`) — are pushed to the box. Your `solve.py`, sources, and unpatched
originals never leave the host; the per-challenge dir on the box is wiped to
exactly that file set on every push, so the binary loads *your* libc, not the
box's system libc.

The generated `solve.py` is thin:

```python
from pwn import *
from pwnsolve import Challenge

chal = Challenge(binary="vuln_patched", libc="libc.so.6", ld="ld.so",
                 target=("addr", 1337), gdbscript="b *main\n")
exe, libc, ld = chal.exe, chal.libc, chal.ld
r = chal.conn()
r.interactive()
```
