"""SSH plumbing: argv builders + file sync to the remote debug box."""
import os
import fnmatch
import shlex
import shutil
import subprocess

# Files the target needs at *runtime* on the box: the binary itself plus every
# shared object / loader it may pull in. Deliberately excludes solve.py, *.py,
# READMEs, unpatched originals, etc. — only these are pushed to the VM.
_SO_PATTERNS = ["*.so", "*.so.*", "ld-*.so*", "ld.so.*", "*ld-linux*", "*.so.[0-9]*"]


def collect_runtime_files(directory, binary=None, libc=None, ld=None):
    """Return the minimal filename list to run ``binary`` on the box."""
    names = []
    for base in (binary, libc, ld):
        if base:
            names.append(os.path.basename(base))
    for f in sorted(os.listdir(directory)):
        p = os.path.join(directory, f)
        if not (os.path.isfile(p) or os.path.islink(p)):
            continue
        if any(fnmatch.fnmatch(f, pat) for pat in _SO_PATTERNS):
            names.append(f)
    seen, out = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def ssh_opts(cfg):
    s = cfg["ssh"]
    return [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "ServerAliveInterval=30",
        "-i", os.path.expanduser(s["key"]),
        "-p", str(s["port"]),
    ]


def ssh_dest(cfg):
    return "%s@%s" % (cfg["ssh"]["user"], cfg["ssh"]["host"])


def ssh_base(cfg, *extra):
    # -T => no pty => an 8-bit clean pipe (required for binary pwn I/O).
    return ["ssh", "-T", *ssh_opts(cfg), *extra, ssh_dest(cfg)]


def run_ssh(cfg, command, **kw):
    return subprocess.run(ssh_base(cfg) + [command], **kw)


def capture(cfg, command, timeout=10):
    """Run a command on the box and return its stdout (empty on failure)."""
    try:
        return subprocess.run(ssh_base(cfg) + [command],
                              capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def ensure_remote_dir(cfg, remote_dir):
    run_ssh(cfg, "mkdir -p %s" % shlex.quote(remote_dir),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def push_files(cfg, local_dir, remote_dir, names, quiet=True):
    """Upload only ``names`` (binary + libs) into ``remote_dir`` (rsync, scp fallback).

    Symlinks (e.g. ``libc.so.6 -> libc-<hash>.so``) are preserved; the real file
    is pushed too as long as it is in ``names``.
    """
    if not names:
        return remote_dir
    # Wipe the (dedicated, per-challenge) dir first so the box holds ONLY these
    # files — never a stray solve.py or unpatched original from an earlier push.
    rd = remote_dir.rstrip("/")
    if rd.startswith("/") and len([x for x in rd.split("/") if x]) >= 2:
        run_ssh(cfg, "rm -rf %s" % shlex.quote(rd),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ensure_remote_dir(cfg, remote_dir)
    dest = "%s:%s/" % (ssh_dest(cfg), remote_dir)
    srcs = [os.path.join(local_dir, n) for n in names]
    out = subprocess.DEVNULL if quiet else None

    if shutil.which("rsync"):
        ssh_cmd = "ssh " + " ".join(shlex.quote(x) for x in ssh_opts(cfg))
        cmd = ["rsync", "-azl", "-e", ssh_cmd, *srcs, dest]
    else:
        scp_opts = [o if o != "-p" else "-P" for o in ssh_opts(cfg)]
        cmd = ["scp", *scp_opts, *srcs, dest]

    subprocess.run(cmd, check=True, stdout=out, stderr=out)
    return remote_dir
