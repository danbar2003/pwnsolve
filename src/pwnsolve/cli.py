"""Console entrypoints: solveinit / solvesync / solveconfig."""
import argparse
import fnmatch
import os
import shutil
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


def _interp_runpath(path):
    """Return (interpreter, runpath) for an ELF, or (None, None)."""
    try:
        from pwn import ELF, context
        context.log_level = "error"
        e = ELF(path, checksec=False)
        interp = (e.linker or b"").decode("latin1")
        rpath = e.runpath or e.rpath
        return interp, (rpath.decode("latin1") if isinstance(rpath, bytes) else rpath)
    except Exception:
        return None, None


def _is_patched(path):
    """True if the binary was patched to load a local loader/libc (pwninit-style)."""
    interp, rpath = _interp_runpath(path)
    if not interp:
        return False
    return interp.startswith("./") or interp.startswith("/tmp") or bool(rpath)


def _elf_candidates(directory, libc, ld):
    entries = sorted(os.listdir(directory))
    return [n for n in entries
            if os.path.isfile(os.path.join(directory, n))
            and not n.endswith((".py", ".so")) and ".so." not in n
            and n not in (libc, ld)
            and _is_elf(os.path.join(directory, n))]


def _detect_files(directory):
    """Detect (base_binary, libc, ld). base_binary prefers the *original* (un-patched)."""
    entries = sorted(os.listdir(directory))

    def first(patterns):
        for pat in patterns:
            for name in entries:
                if fnmatch.fnmatch(name, pat) and os.path.isfile(os.path.join(directory, name)):
                    return name
        return None

    libc = first(["libc*.so*", "*libc*.so*"])
    ld = first(["ld-*.so*", "ld.so*", "*ld-linux*"])
    elfs = _elf_candidates(directory, libc, ld)
    base = next((n for n in elfs if "patched" not in n), None) or (elfs[0] if elfs else None)
    return base, libc, ld


def _best_binary(directory, base, libc, ld):
    """Pick a binary to ship: an already-correctly-patched ELF, else the base."""
    for n in _elf_candidates(directory, libc, ld):
        if _is_patched(os.path.join(directory, n)):
            return n
    return base


def _patch_on_host(directory, base, libc, ld):
    """Patch ``base`` on the host with pwninit so it uses the provided libc/ld."""
    if not (base and libc and shutil.which("pwninit")):
        return None
    # pwninit aborts if the artifacts it manages already exist; clear them so
    # re-running is idempotent (safe: it recreates both).
    for stale in (base + "_patched", "libc.so.6"):
        sp = os.path.join(directory, stale)
        if os.path.islink(sp) or (stale.endswith("_patched") and os.path.isfile(sp)):
            try:
                os.remove(sp)
            except OSError:
                pass
    cmd = ["pwninit", "--bin", base, "--libc", libc, "--no-template"]
    if ld:
        cmd += ["--ld", ld]
    print("[*] patching on host: %s" % " ".join(cmd))
    subprocess.run(cmd, cwd=directory, check=False)
    out = base + "_patched"
    if os.path.exists(os.path.join(directory, out)) and _is_patched(os.path.join(directory, out)):
        return out
    return None


def _render_template(**kw):
    tmpl = resources.files("pwnsolve").joinpath("templates/solve.py.tmpl").read_text()
    return tmpl.format(**kw)


# --------------------------------------------------------------------------
# solveinit
# --------------------------------------------------------------------------
def init_cmd(argv=None):
    p = argparse.ArgumentParser(
        prog="solveinit",
        description="Patch the binary on the host, scaffold solve.py, and push the "
                    "binary + libs (only) to the debug box.")
    p.add_argument("name", nargs="?", help="challenge name (default: current directory name)")
    p.add_argument("--binary", help="target binary (autodetected if omitted)")
    p.add_argument("--libc", help="libc shared object (autodetected if omitted)")
    p.add_argument("--ld", help="ld/loader (autodetected if omitted)")
    p.add_argument("--host", default="addr", help="remote CTF host (default: addr)")
    p.add_argument("--port", type=int, default=1337, help="remote CTF port (default: 1337)")
    p.add_argument("--no-patch", action="store_true",
                   help="don't run pwninit; use an existing (patched) binary as-is")
    p.add_argument("--no-sync", action="store_true", help="do not upload to the box")
    p.add_argument("--force", action="store_true", help="overwrite an existing solve.py")
    p.add_argument("--edit", action="store_true",
                   help="open the pwnsolve config in $EDITOR and exit")
    args = p.parse_args(argv)

    if args.edit:
        return config_cmd(["--edit"])

    cfg = load_config()
    if cfg["ssh"]["host"] in ("127.0.0.1", "your.box.example"):
        print("[!] config still has the placeholder box (host=%s). Set yours:\n"
              "    solveconfig --edit   (%s)" % (cfg["ssh"]["host"], CONFIG_PATH))
    cwd = os.getcwd()

    base, dlibc, dld = _detect_files(cwd)
    libc = args.libc or dlibc
    ld = args.ld or dld

    # Decide which binary to ship. Patch on the HOST so it uses the provided libc.
    binary = args.binary
    if not binary:
        if libc and not args.no_patch:
            patched = _patch_on_host(cwd, base, libc, ld)
            if patched:
                binary = patched
                # pwninit may have created the libc.so.6 symlink / fetched ld
                _, dlibc2, dld2 = _detect_files(cwd)
                ld = ld or dld2
            elif shutil.which("pwninit"):
                print("[!] pwninit did not produce a patched binary; falling back")
        if not binary:
            binary = _best_binary(cwd, base, libc, ld)

    if not binary:
        p.error("could not detect a target binary; pass --binary")

    if libc and not _is_patched(os.path.join(cwd, binary)):
        print("[!] %s is NOT patched for ./%s — it will load the box's system libc.\n"
              "    Re-run with pwninit/patchelf (default) or pass --binary <patched>." %
              (binary, os.path.basename(libc)))

    name = args.name or os.path.basename(cwd.rstrip("/")) or "chal"

    solve_path = os.path.join(cwd, "solve.py")
    if os.path.exists(solve_path) and not args.force:
        print("[!] solve.py already exists (use --force to overwrite); leaving it untouched")
    else:
        text = _render_template(binary=binary, libc=libc, ld=ld, host=args.host, port=args.port)
        with open(solve_path, "w") as f:
            f.write(text)
        os.chmod(solve_path, 0o755)
        print("[+] wrote %s" % solve_path)

    print("    binary=%s  libc=%s  ld=%s" % (binary, libc, ld))

    remote_dir = "%s/%s" % (cfg["ssh"]["remote_base"].rstrip("/"), name)
    if not args.no_sync:
        names = _remote.collect_runtime_files(cwd, binary, libc, ld)
        print("[*] pushing %s -> %s:%s" % (names, _remote.ssh_dest(cfg), remote_dir))
        try:
            _remote.push_files(cfg, cwd, remote_dir, names)
            print("[+] pushed (binary + libs only)")
        except Exception as e:
            print("[!] push failed: %s" % e)

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
        description="Push the current challenge's binary + libs (only) to the debug box.")
    p.add_argument("name", nargs="?", help="challenge name (default: current directory name)")
    args = p.parse_args(argv)

    cfg = load_config()
    cwd = os.getcwd()
    name = args.name or os.path.basename(cwd.rstrip("/")) or "chal"
    remote_dir = "%s/%s" % (cfg["ssh"]["remote_base"].rstrip("/"), name)

    base, libc, ld = _detect_files(cwd)
    binary = _best_binary(cwd, base, libc, ld)
    names = _remote.collect_runtime_files(cwd, binary, libc, ld)
    print("[*] pushing %s -> %s:%s" % (names, _remote.ssh_dest(cfg), remote_dir))
    try:
        _remote.push_files(cfg, cwd, remote_dir, names, quiet=False)
        print("[+] pushed (binary + libs only)")
        return 0
    except Exception as e:
        print("[!] push failed: %s" % e)
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
