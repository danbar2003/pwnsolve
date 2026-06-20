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

```bash
solveconfig --edit        # ~/.config/pwnsolve/config.toml
```

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
```

## Per challenge

```bash
cd ~/ctf/some_challenge
solveinit                 # detect binary/libc/ld, write solve.py, sync to the box
#   solveinit --pwninit   # run pwninit first
#   solveinit --host 1.2.3.4 --port 31337

python3 solve.py LOCAL    # run on the box, drive I/O locally (no debugger)
python3 solve.py GDB      # debug via gdbserver, local pwndbg attaches
python3 solve.py          # connect to the real CTF server

solvesync                 # re-upload after re-patching / editing files
```

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
