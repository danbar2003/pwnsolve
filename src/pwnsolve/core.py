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
import subprocess

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
        names = _remote.collect_runtime_files(
            self.local_dir, self.binary,
            os.path.basename(self.libc.path) if self.libc else None,
            os.path.basename(self.ld.path) if self.ld else None)
        _remote.push_files(self.cfg, self.local_dir, self.remote_dir, names, quiet=quiet)
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
        gslog = "/tmp/.pwnsolve-gdbserver-%d.log" % port
        if under_gdbserver:
            # An interrupted prior session can leave gdbserver holding the port on
            # the box (and a stale -L tunnel locally). Free both before launching.
            _remote.run_ssh(self.cfg, "fuser -k %d/tcp 2>/dev/null; sleep 0.2; true" % port,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._free_local_port(port)
            # gdbserver's stderr (banner + errors) -> remote log, so the I/O tube
            # stays clean but startup failures are still recoverable.
            run = "exec gdbserver --once 127.0.0.1:%d %s 2>%s" % (port, binq, shlex.quote(gslog))
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
            if r.poll(block=False) is not None:   # gdbserver died on startup
                err = _remote.capture(self.cfg, "cat %s 2>/dev/null" % shlex.quote(gslog)).strip()
                log.error("gdbserver failed to start on the box:\n    %s",
                          err.replace("\n", "\n    ") or "(no output; check the box manually)")
            self._launch_debugger(port)
            self._wait_for_attach(port)
            log.info("%s attached; the binary stays paused until you `continue`.",
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

    def _wait_for_attach(self, port, timeout=120):
        """Block until the local debugger has connected to gdbserver.

        Prevents the caller from driving (and crashing) the target before the
        debugger is in. Detected via an ESTABLISHED connection on the forwarded
        port; falls back to a short sleep if lsof is unavailable.
        """
        from pwn import log
        if not shutil.which("lsof"):
            time.sleep(3)
            return False
        deadline = time.time() + timeout
        with log.progress("Waiting for %s to attach" % self.cfg["debug"]["debugger"]) as pr:
            while time.time() < deadline:
                if self._port_established(port):
                    pr.success("attached")
                    return True
                time.sleep(0.3)
            pr.failure("timed out after %ds — continuing without confirmation" % timeout)
        return False

    @staticmethod
    def _port_established(port):
        try:
            out = subprocess.run(["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:ESTABLISHED"],
                                 capture_output=True, text=True, timeout=5).stdout
        except Exception:
            return False
        return bool(out.strip())

    @staticmethod
    def _free_local_port(port):
        """Kill a stale local ssh -L tunnel left listening on ``port``."""
        if not shutil.which("lsof"):
            return
        try:
            out = subprocess.run(
                ["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN", "-Fpc"],
                capture_output=True, text=True, timeout=5).stdout
        except Exception:
            return
        pid = None
        for line in out.splitlines():
            if line.startswith("p"):
                pid = line[1:]
            elif line.startswith("c") and line[1:].startswith("ssh") and pid:
                try:
                    os.kill(int(pid), 9)
                except (OSError, ValueError):
                    pass

    @staticmethod
    def _safe_close(r):
        try:
            r.close()
        except Exception:
            pass
