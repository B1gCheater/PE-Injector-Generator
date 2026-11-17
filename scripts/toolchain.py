#!/usr/bin/env python3
"""scripts/toolchain.py — toolchain detection + compile wrapper (P0).

Two responsibilities:
1. detect() probes the local toolchain; running `python scripts/toolchain.py`
   prints the result and writes scripts/toolchain.json for the generator.
2. compile_loader() builds a single x64 Windows EXE, always via
   subprocess.run(list) (never through a shell).

blueprint §2 invariants:
- Use `-` prefixed args everywhere (avoids Git Bash rewriting /nologo).
- `-subsystem` must come AFTER `-link`.
- The bundled zstd static lib is MinGW-built, so linking it requires
  `-alternatename:___chkstk_ms=__chkstk`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
CONFIG = Path(__file__).resolve().parent / "toolchain.json"


def _run(args, timeout=60):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


def _find_msvc() -> str | None:
    """Return the MSVC toolset root (containing lib/x64), highest version wins."""
    base = Path(r"C:\Program Files\Microsoft Visual Studio")
    if not base.exists():
        return None
    found = [m for m in base.glob("*/*/VC/Tools/MSVC/*") if (m / "lib" / "x64").is_dir()]
    if not found:
        return None
    found.sort(key=lambda p: p.name, reverse=True)
    return str(found[0])


def _find_sdk() -> str | None:
    """Return the Windows SDK Lib root (containing um/x64), highest version wins."""
    base = Path(r"C:\Program Files (x86)\Windows Kits\10\Lib")
    if not base.exists():
        return None
    found = [d for d in base.iterdir() if (d / "um" / "x64").is_dir()]
    if not found:
        return None
    found.sort(key=lambda p: p.name, reverse=True)
    return str(found[0])


def _find_zstd() -> str | None:
    """Return the zstd root (with include/zstd.h and static/libzstd_static.lib)."""
    for cand in (r"C:\software\zstd-v1.5.7-win64", r"D:\sourcecode\zstd-v1.5.7-win64"):
        p = Path(cand)
        if (p / "include" / "zstd.h").is_file() and (p / "static" / "libzstd_static.lib").is_file():
            return str(p)
    return None


def _find_tool(*names: str) -> str | None:
    for name in names:
        p = TOOLS / name
        if p.is_file():
            return str(p)
        w = shutil.which(name)
        if w:
            return w
    return None


def detect() -> dict:
    tc: dict = {"ok": True, "errors": []}

    clang_cl = shutil.which("clang-cl")
    lld_link = shutil.which("lld-link")
    tc["clang_cl"] = clang_cl
    tc["lld_link"] = lld_link
    if not clang_cl or not lld_link:
        tc["ok"] = False
        tc["errors"].append("clang-cl/lld-link not on PATH")

    if clang_cl:
        _, ver, _ = _run([clang_cl, "--version"])
        tc["clang_version"] = ver.splitlines()[0] if ver else "unknown"
    else:
        tc["clang_version"] = "unknown"

    msvc = _find_msvc()
    tc["msvc"] = msvc
    if not msvc:
        tc["ok"] = False
        tc["errors"].append("MSVC (with lib/x64) not found")

    sdk = _find_sdk()
    tc["sdk"] = sdk
    if not sdk:
        tc["ok"] = False
        tc["errors"].append("Windows SDK (with um/x64) not found")

    tc["bin2source"] = _find_tool("bin2source.exe")
    tc["zstd"] = _find_zstd()
    tc["upx"] = _find_tool("upx.exe")
    tc["shellcode_generator"] = _find_tool("shellcode-generator.exe")

    _, py, _ = _run([sys.executable, "--version"])
    tc["python_version"] = py or "unknown"

    return tc


def compile_loader(
    sources,
    out_exe,
    subsystem: str = "windows",
    debug: bool = False,
    static_crt: bool = False,
    use_zstd: bool = False,
    extra_include=(),
    extra_libs=(),
    extra_cflags=(),
    tc: dict | None = None,
):
    """Build one x64 Windows EXE.

    sources: list of .c/.cpp files (clang-cl picks the language by extension).
    Returns a subprocess.CompletedProcess; returncode == 0 means success.
    """
    tc = tc or detect()
    if not tc.get("ok"):
        raise RuntimeError("toolchain unavailable: " + "; ".join(tc.get("errors", [])))

    cmd = [tc["clang_cl"], "-nologo"]
    cmd += ["-Od", "-Zi"] if debug else ["-O2"]
    # clang-cl 23.x rejects -fno-exceptions/-fno-rtti; use the MSVC spellings.
    cmd += ["/EHs-c-", "/GR-"]
    cmd += list(extra_cflags)
    cmd += ["-MT"] if static_crt else ["-MD"]
    for inc in extra_include:
        cmd += ["-I", str(inc)]
    if use_zstd and tc.get("zstd"):
        cmd += ["-I", str(Path(tc["zstd"]) / "include")]
    cmd += [str(s) for s in sources]
    cmd += [f"-Fe:{out_exe}", "-fuse-ld=lld"]

    cmd += ["-link", f"-subsystem:{subsystem}"]
    if not debug:
        cmd += ["-opt:ref", "-opt:icf"]
    cmd += [f"-libpath:{tc['sdk']}/um/x64", f"-libpath:{tc['msvc']}/lib/x64"]

    libs = ["kernel32.lib", "user32.lib", "advapi32.lib", "wtsapi32.lib"]
    if use_zstd and tc.get("zstd"):
        cmd += [f"-libpath:{Path(tc['zstd']) / 'static'}"]
        cmd += ["-alternatename:___chkstk_ms=__chkstk"]
        libs.append("libzstd_static.lib")
    libs.extend(extra_libs)
    cmd += libs

    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    tc = detect()
    print(json.dumps(tc, indent=2, ensure_ascii=False))
    CONFIG.write_text(json.dumps(tc, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote {CONFIG}")
    sys.exit(0 if tc["ok"] else 1)


if __name__ == "__main__":
    main()
