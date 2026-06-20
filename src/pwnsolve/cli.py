"""Console entrypoints: solveinit / solvesync / solveconfig."""
import argparse
import glob
import os
import subprocess
import sys
from importlib import resources

from .config import ensure_config, load_config, CONFIG_PATH
from . import remote as _remote


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _detect_files(directory):
    """Best-effort detection of (binary, libc, ld) in a challenge directory."""
    entries = sorted(os.listdir(directory))

    def first(patterns):
        for pat in patterns:
            for name in entries:
                if glob.fnmatch.fnmatch(name, pat) and os.path.isfile(os.path.join(directory, name)):
                    return name
        return None

    libc = first(["libc*.so*", "libc-*.so", "*libc*.so*"])
    ld = first(["ld-*.so*", "ld.so*", "*ld-linux*"])

    # binary: an ELF that is not the libc/ld/a shared object, preferring *_patched.
    elfs = [n for n in entries
            if os.path.isfile(os.path.join(directory, n))
            and not n.endswith((".py", ".so")) and ".so." not in n
            and n not in (libc, ld)
            and _is_elf(os.path.join(directory, n))]
    binary = None
    for n in elfs:
        if "patched" in n:
            binary = n
            break
    if binary is None and elfs:
        binary = elfs[0]
    return binary, libc, ld


def _render_template(**kw):
    tmpl = resources.files("pwnsolve").joinpath("templates/solve.py.tmpl").read_text()
    return tmpl.format(**kw)


# --------------------------------------------------------------------------
# solveinit
# --------------------------------------------------------------------------
def init_cmd(argv=None):
    p = argparse.ArgumentParser(
        prog="solveinit",
        description="Scaffold a solve.py for the current challenge and sync it to the debug box.")
    p.add_argument("name", nargs="?", help="challenge name (default: current directory name)")
    p.add_argument("--binary", help="target binary (autodetected if omitted)")
    p.add_argument("--libc", help="libc shared object (autodetected if omitted)")
    p.add_argument("--ld", help="ld/loader (autodetected if omitted)")
    p.add_argument("--host", default="addr", help="remote CTF host (default: addr)")
    p.add_argument("--port", type=int, default=1337, help="remote CTF port (default: 1337)")
    p.add_argument("--pwninit", action="store_true",
                   help="run pwninit first (patch binary + fetch ld) if available")
    p.add_argument("--no-sync", action="store_true", help="do not upload to the box")
    p.add_argument("--force", action="store_true", help="overwrite an existing solve.py")
    args = p.parse_args(argv)

    cfg = load_config()
    cwd = os.getcwd()

    if args.pwninit:
        import shutil
        if shutil.which("pwninit"):
            print("[*] running pwninit ...")
            subprocess.run(["pwninit"], check=False)
        else:
            print("[!] pwninit not found on PATH; skipping")

    binary = args.binary or None
    libc = args.libc
    ld = args.ld
    if not binary or not libc or not ld:
        db, dl, dld = _detect_files(cwd)
        binary = binary or db
        libc = libc or dl
        ld = ld or dld

    if not binary:
        p.error("could not detect a target binary; pass --binary")

    name = args.name or os.path.basename(cwd.rstrip("/")) or "chal"

    solve_path = os.path.join(cwd, "solve.py")
    if os.path.exists(solve_path) and not args.force:
        print("[!] solve.py already exists (use --force to overwrite); leaving it untouched")
    else:
        text = _render_template(binary=binary, libc=libc, ld=ld,
                                 host=args.host, port=args.port)
        with open(solve_path, "w") as f:
            f.write(text)
        os.chmod(solve_path, 0o755)
        print("[+] wrote %s" % solve_path)

    print("    binary=%s  libc=%s  ld=%s" % (binary, libc, ld))

    remote_dir = "%s/%s" % (cfg["ssh"]["remote_base"].rstrip("/"), name)
    if not args.no_sync:
        print("[*] syncing -> %s:%s" % (_remote.ssh_dest(cfg), remote_dir))
        try:
            _remote.sync(cfg, cwd, remote_dir)
            print("[+] synced")
        except Exception as e:
            print("[!] sync failed: %s" % e)

    print("\nNext:")
    print("    python3 solve.py LOCAL   # run on the box, drive I/O")
    print("    python3 solve.py GDB     # debug with %s via gdbserver" % cfg["debug"]["debugger"])
    return 0


# --------------------------------------------------------------------------
# solvesync
# --------------------------------------------------------------------------
def sync_cmd(argv=None):
    p = argparse.ArgumentParser(
        prog="solvesync",
        description="Upload the current challenge directory to the debug box.")
    p.add_argument("name", nargs="?", help="challenge name (default: current directory name)")
    args = p.parse_args(argv)

    cfg = load_config()
    cwd = os.getcwd()
    name = args.name or os.path.basename(cwd.rstrip("/")) or "chal"
    remote_dir = "%s/%s" % (cfg["ssh"]["remote_base"].rstrip("/"), name)
    print("[*] syncing %s -> %s:%s" % (cwd, _remote.ssh_dest(cfg), remote_dir))
    try:
        _remote.sync(cfg, cwd, remote_dir, quiet=False)
        print("[+] synced")
        return 0
    except Exception as e:
        print("[!] sync failed: %s" % e)
        return 1


# --------------------------------------------------------------------------
# solveconfig
# --------------------------------------------------------------------------
def config_cmd(argv=None):
    p = argparse.ArgumentParser(
        prog="solveconfig",
        description="Show or edit the pwnsolve debug-box configuration.")
    p.add_argument("--edit", action="store_true", help="open the config in $EDITOR")
    p.add_argument("--path", action="store_true", help="print the config path only")
    args = p.parse_args(argv)

    ensure_config()
    if args.path:
        print(CONFIG_PATH)
        return 0
    if args.edit:
        editor = os.environ.get("EDITOR", "vi")
        return subprocess.call([editor, str(CONFIG_PATH)])

    print("# %s\n" % CONFIG_PATH)
    print(CONFIG_PATH.read_text())
    return 0


if __name__ == "__main__":
    sys.exit(init_cmd())
