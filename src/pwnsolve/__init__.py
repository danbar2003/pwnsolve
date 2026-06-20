"""pwnsolve — drive a remote pwn target locally, debug it via remote gdbserver.

Typical solve.py:

    from pwn import *
    from pwnsolve import Challenge

    chal = Challenge(binary="vuln_patched", libc="libc.so.6", ld="ld.so",
                     target=("host", 1337), gdbscript="b *main\\n")
    exe, libc, ld = chal.exe, chal.libc, chal.ld

    r = chal.conn()
    r.interactive()
"""
from .core import Challenge
from .config import load_config, CONFIG_PATH

__all__ = ["Challenge", "load_config", "CONFIG_PATH"]
__version__ = "0.1.0"
