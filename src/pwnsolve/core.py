"""The Challenge helper: connect to a target that runs on the remote box.

Modes (selected via pwntools ``args`` on the solve script command line):

    python3 solve.py          -> remote(TARGET)            the real CTF server
    python3 solve.py LOCAL    -> binary runs on the box, I/O driven locally
    python3 solve.py GDB      -> binary runs under gdbserver on the box,
                                 a LOCAL debugger (pwndbg) attaches over SSH
"""
import os
import time
import atexit
import shlex
import shutil
import tempfile

from . import remote as _remote
from . import terminal as _terminal
from .config import load_config

# pwntools ELF arch/bits -> gdb "set architecture" string.
_GDB_ARCH = {
    ("amd64", 64): "i386:x86-64",
    ("i386", 32): "i386",
    ("aarch64", 64): "aarch64",
    ("arm", 32): "arm",
    ("mips", 32): "mips",
    ("mips", 64): "mips:isa64",
    ("powerpc", 32): "powerpc:common",
    ("powerpc", 64): "powerpc:common64",
}


def _resolve_debugger(name):
    """Map a config 'debugger' value to a runnable command prefix (list)."""
    name = (name or "pwndbg").strip()
    if name in ("pwndbg",):
        path = shutil.which("pwndbg") or os.path.expanduser("~/.local/bin/pwndbg")
        return [path if os.path.exists(path) else "gdb"]
    if name in ("gdb",):
        return ["gdb"]
    if name in ("gef",):
        gef = os.path.expanduser("~/.gef.py")
        return ["gdb", "-q", "-ex", "source %s" % gef] if os.path.exists(gef) else ["gdb"]
    # explicit path or program name
    return [name]


class Challenge:
    def __init__(self, binary, libc=None, ld=None, target=None, name=None,
                 remote_dir=None, gdbscript="", autosync=True, cfg=None):
        from pwn import ELF, context

        self.cfg = cfg or load_config()
        self.local_dir = os.getcwd()
        self.binary = binary
        self.binpath = os.path.join(self.local_dir, binary)

        self.exe = ELF(self.binpath, checksec=False)
        self.libc = ELF(os.path.join(self.local_dir, libc), checksec=False) if libc else None
        self.ld = ELF(os.path.join(self.local_dir, ld), checksec=False) if ld else None
        context.binary = self.exe

        self.target = tuple(target) if target else None
        self.name = name or os.path.basename(self.local_dir.rstrip("/")) or "chal"
        base = self.cfg["ssh"]["remote_base"].rstrip("/")
        self.remote_dir = remote_dir or "%s/%s" % (base, self.name)
        self.gdbscript = gdbscript
        self.autosync = autosync

    # -- public ------------------------------------------------------------
    def conn(self):
        from pwn import args, remote, log

        if args.GDB:
            return self._spawn(under_gdbserver=True)
        if args.LOCAL:
            return self._spawn(under_gdbserver=False)
        if not self.target:
            log.error("No remote target set. Pass target=(host, port) or run with LOCAL/GDB.")
        return remote(*self.target)

    def sync(self, quiet=True):
        _remote.sync(self.cfg, self.local_dir, self.remote_dir, quiet=quiet)
        return self.remote_dir

    # -- internals ---------------------------------------------------------
    def _spawn(self, under_gdbserver):
        from pwn import process, log

        self._ensure_local_exec()
        if self.autosync:
            try:
                self.sync()
            except Exception as e:
                log.warn("autosync failed (%s); using whatever is already on the box" % e)

        port = int(self.cfg["debug"]["gdb_port"])
        binq = shlex.quote("./" + self.binary)
        cd = "cd %s" % shlex.quote(self.remote_dir)
        # The binary (and patched loader, if any) need the exec bit on the box;
        # rsync mirrors local perms, and CTF drops often arrive non-executable.
        targets = [binq]
        if self.ld:
            targets.append(shlex.quote("./" + os.path.basename(self.ld.path)))
        chmod = "chmod +x %s" % " ".join(targets)
        if under_gdbserver:
            run = "exec gdbserver --once 127.0.0.1:%d %s 2>/dev/null" % (port, binq)
            argv = _remote.ssh_base(self.cfg, "-L", "%d:127.0.0.1:%d" % (port, port)) + \
                ["%s && %s && %s" % (cd, chmod, run)]
        else:
            argv = _remote.ssh_base(self.cfg) + ["%s && %s && exec %s" % (cd, chmod, binq)]

        # Label the tube with the binary name so the SSH transport stays invisible
        # in pwntools' "Starting ... / stopped ..." lines.
        r = process(argv, display=os.path.basename(self.binary))
        atexit.register(lambda: self._safe_close(r))

        if under_gdbserver:
            time.sleep(1.0)              # let gdbserver bind + the -L tunnel settle
            self._launch_debugger(port)
            log.info("%s launching; the binary stays paused until you `continue`.",
                     self.cfg["debug"]["debugger"])
        return r

    def _launch_debugger(self, port):
        scr = tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False)
        scr.write("set debuginfod enabled %s\n" % self.cfg["debug"].get("debuginfod", "on"))
        arch = _GDB_ARCH.get((self.exe.arch, self.exe.bits))
        if arch:
            scr.write("set architecture %s\n" % arch)
        scr.write("set sysroot %s\n" % self.local_dir)
        scr.write("set solib-search-path %s\n" % self.local_dir)
        scr.write("target remote 127.0.0.1:%d\n" % port)
        scr.write(self.gdbscript or "")
        scr.flush(); scr.close()

        dbg = _resolve_debugger(self.cfg["debug"]["debugger"])
        cmd = " ".join(shlex.quote(x) for x in dbg) + \
            " -q %s -x %s" % (shlex.quote(self.binpath), shlex.quote(scr.name))
        _terminal.launch(cmd, prefer=self.cfg["debug"].get("terminal", "auto"))

    def _ensure_local_exec(self):
        import stat
        for p in [self.binpath] + ([self.ld.path] if self.ld else []):
            try:
                os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except OSError:
                pass

    @staticmethod
    def _safe_close(r):
        try:
            r.close()
        except Exception:
            pass
