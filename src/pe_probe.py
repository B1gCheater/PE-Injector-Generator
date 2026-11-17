#!/usr/bin/env python3
"""src/pe_probe.py — dependency-free PE parsing.

Pre-flight inspection of dll/exe payloads. This product only accepts x64
(Machine == 0x8664).

Inspected fields:
- Machine (x64 / x86 / arm64 ...)
- DLL vs EXE (FileHeader.Characteristics IMAGE_FILE_DLL bit)
- whether .reloc is present (needed for EXE self-mapping)
- whether it is a .NET assembly (CLR COM directory non-empty)
- subsystem (GUI / console)

Also usable standalone: python src/pe_probe.py <file>
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

MACHINE = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "arm",
    0x01C4: "armv7",
    0xAA64: "arm64",
    0x0200: "ia64",
}

SUBSYSTEM = {
    1: "native",
    2: "windows-gui",
    3: "windows-console",
}

# Offset of the DataDirectory array inside the OptionalHeader, per magic.
_DD_OFFSET = {0x10B: 96, 0x20B: 112}
_DD_BASERELOC = 5  # Base Relocation Table
_DD_CLR = 14       # COM Descriptor Directory


class PEError(Exception):
    pass


def parse_pe(path: str | Path) -> dict:
    p = Path(path)
    data = p.read_bytes()

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError(f"not a valid PE (missing MZ header): {p}")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise PEError(f"missing PE signature: {p}")

    fh = e_lfanew + 4
    machine = struct.unpack_from("<H", data, fh)[0]
    n_sections = struct.unpack_from("<H", data, fh + 2)[0]
    size_opt = struct.unpack_from("<H", data, fh + 16)[0]
    characteristics = struct.unpack_from("<H", data, fh + 18)[0]

    oh = fh + 20
    magic = struct.unpack_from("<H", data, oh)[0]
    if magic not in _DD_OFFSET:
        raise PEError(f"unsupported OptionalHeader magic 0x{magic:X}")

    subsystem = struct.unpack_from("<H", data, oh + 68)[0]
    dd = oh + _DD_OFFSET[magic]

    reloc_va, reloc_size = struct.unpack_from("<II", data, dd + _DD_BASERELOC * 8)
    clr_va, clr_size = struct.unpack_from("<II", data, dd + _DD_CLR * 8)

    sec_off = oh + size_opt
    sections = []
    for i in range(n_sections):
        s = sec_off + i * 40
        name = data[s : s + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize = struct.unpack_from("<I", data, s + 8)[0]
        vaddr = struct.unpack_from("<I", data, s + 12)[0]
        rawsize = struct.unpack_from("<I", data, s + 16)[0]
        rawptr = struct.unpack_from("<I", data, s + 20)[0]
        sections.append({"name": name, "vaddr": vaddr, "vsize": vsize,
                         "rawsize": rawsize, "rawptr": rawptr})

    arch = MACHINE.get(machine, f"unknown(0x{machine:X})")
    return {
        "path": str(p),
        "size": len(data),
        "machine": machine,
        "arch": arch,
        "is_x64": machine == 0x8664,
        "is_dll": bool(characteristics & 0x2000),
        "subsystem": subsystem,
        "subsystem_name": SUBSYSTEM.get(subsystem, f"unknown({subsystem})"),
        "has_reloc": bool(reloc_va and reloc_size),
        "reloc_va": reloc_va,
        "reloc_size": reloc_size,
        "is_dotnet": bool(clr_va and clr_size),
        "n_sections": n_sections,
        "sections": sections,
    }


def main():
    if len(sys.argv) != 2:
        print("usage: python src/pe_probe.py <file>")
        sys.exit(2)
    try:
        info = parse_pe(sys.argv[1])
    except PEError as e:
        print(f"ERROR: {e}")
        sys.exit(3)
    print(json.dumps(info, indent=2, ensure_ascii=False))
    if not info["is_x64"]:
        print(f"\n[REJECT] not x64 ({info['arch']})")
    elif info["is_dotnet"]:
        print("\n[REJECT] .NET assembly, self-mapping unsupported")
    else:
        kind = "DLL" if info["is_dll"] else "EXE"
        reloc = "with" if info["has_reloc"] else "without"
        print(f"\n[OK] x64 {kind}, {reloc} .reloc")


if __name__ == "__main__":
    main()
