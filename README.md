# PE-Injector-Generator

Build several payloads (shellcode / DLL / EXE) into a single Windows x64 EXE that
injects or self-boots them as declared — with optional compression, encryption,
and TrustedInstaller elevation.

The generator is a Python orchestration layer. It parses a job table, embeds the
payloads with `bin2source`, renders the loader config, compiles one C++ loader
with clang-cl, and verifies the result. The output is a single, self-contained
EXE (or raw shellcode with `--shellcode-final`).

## Features

- **Three payload kinds** — raw shellcode, DLL, and EXE.
- **Local & remote delivery**
  - shellcode: run locally, or inject into a remote process.
  - DLL: load locally (memory map), or manual-map into a remote process.
  - EXE: self-map into the loader process.
- **Payload transforms** (all off by default = raw hex array)
  - compression: zstd or deflate
  - base64 encoding
  - AES-256 encryption (`--password`, key = SHA-256 of the password)
- **TrustedInstaller elevation** (`-ti` / job `ti=1`) — best-effort thread-level
  impersonation via TiLib; falls back to the caller's (admin) token on failure.
- **Runtime integrity** — `--verify` digests each decoded payload and skips a
  corrupt one.
- **EXE arguments** — pass a command line to a self-mapped EXE (`arg=...`).
- **Multiple jobs** — one loader can carry several payloads, executed in order.
- **`--manifest`** — read the whole job table from a JSON file.
- **`--shellcode-final`** — convert the final EXE to raw shellcode.

## Quick start

```sh
# run shellcode locally
python Injector-Generator.py --job "type=shellcode,file=payload.bin"

# manual-map a DLL into explorer.exe, compressed + base64
python Injector-Generator.py --job "type=dll,file=payload.dll,target=explorer" -z zstd -b

# self-map an EXE with a command line, elevated to TrustedInstaller
python Injector-Generator.py --job "type=exe,file=payload.exe,arg=--flag,ti=1"
```

Run `python Injector-Generator.py -h` for the full option reference (colored).

## Job syntax

`--job` takes one `key=value,key=value` spec and is repeatable; execution order
equals the order given. Quote values that contain spaces or commas.

| key      | meaning                                                    |
|----------|------------------------------------------------------------|
| `type`   | `shellcode` \| `dll` \| `exe` (required)                   |
| `file`   | payload path (required)                                    |
| `target` | process name to inject into; omit to run locally           |
| `export` | DLL export to call after `DllMain` (dll only)              |
| `arg`    | EXE command-line argument; repeatable (exe only)           |
| `wait`   | `1` = wait for the target process to appear                |
| `ti`     | `1` = TrustedInstaller impersonation; `0` = off (default)  |

## Requirements

- Windows x64, elevated Administrator for TrustedInstaller elevation.
- **Toolchain** (auto-detected): LLVM `clang-cl` + `lld-link`, MSVC headers/libs,
  Windows SDK, Python 3.
- **Tools** (pre-built in `tools/`): `bin2source`, `shellcode-generator`, `upx`.
- **zstd** static library (only for `-z zstd`): `zstd.h` + `libzstd_static.lib`
  (see the toolchain probe; not shipped in this repo).

## Directory layout

```
Injector-Generator.py   generator entry point
src/loader/             C++ loader + PIC stubs (compiled into the product)
src/pe_probe.py         x64 PE validation
scripts/toolchain.py    toolchain detection & compile driver
vendor/ti/              TiLib (TrustedInstaller token library)
tools/                  pre-built helper tools
```

## Notes

- Code and output are English-only, UTF-8. Internal Chinese design docs live in
  `docs/` and are not part of the repository.
- This is an authorized maintenance/research tool. It performs no AV evasion and
  no persistence, and is intended for isolated test environments only.

## License

Private for now; a license will be chosen before the repository goes public.
Third-party components under `src/loader/` keep their own licenses
(tiny-AES-c is Unlicense; miniz is MIT).
