"""SSH plumbing: argv builders + file sync to the remote debug box."""
import os
import shlex
import shutil
import subprocess


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


def ensure_remote_dir(cfg, remote_dir):
    run_ssh(cfg, "mkdir -p %s" % shlex.quote(remote_dir),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def sync(cfg, local_dir, remote_dir, quiet=True):
    """Mirror ``local_dir`` to ``remote_dir`` on the box (rsync, scp fallback)."""
    ensure_remote_dir(cfg, remote_dir)
    dest = "%s:%s/" % (ssh_dest(cfg), remote_dir)
    src = local_dir.rstrip("/") + "/"
    out = subprocess.DEVNULL if quiet else None

    if shutil.which("rsync"):
        ssh_cmd = "ssh " + " ".join(shlex.quote(x) for x in ssh_opts(cfg))
        cmd = ["rsync", "-az", "--delete", "-e", ssh_cmd,
               "--exclude", "__pycache__", "--exclude", ".git",
               "--exclude", "*.pyc", src, dest]
    else:
        # scp uses -P (uppercase) for the port; copy directory contents.
        scp_opts = [o if o != "-p" else "-P" for o in ssh_opts(cfg)]
        cmd = ["scp", "-r", *scp_opts, src + ".", dest]

    subprocess.run(cmd, check=True, stdout=out, stderr=out)
    return remote_dir
