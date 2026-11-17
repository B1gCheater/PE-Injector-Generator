"""新设备编译链路验证（2026-11-14）。

验证两件事：
1. clang-cl + lld-link 能产出 GUI 子系统 PE（新路径：MSVC 18 Professional）
2. MinGW 版 libzstd_static.lib + -alternatename 开关在新机仍然可用

用 subprocess.run(list) 传参，不经 shell —— 这正是未来生成器的调用方式。
"""
import os
import struct
import subprocess
import sys

VERIFY = r"D:\project\PE-Injector-Generator\temp\verify"
MSVC_LIB = r"C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Tools\MSVC\14.51.36231\lib\x64"
SDK_LIB = r"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64"
ZSTD_INC = r"C:\software\zstd-v1.5.7-win64\include"
ZSTD_LIB = r"C:\software\zstd-v1.5.7-win64\static"


def run(args):
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        print("STDOUT:", r.stdout)
        print("STDERR:", r.stderr)
        sys.exit(r.returncode)
    if r.stdout.strip():
        print(r.stdout.strip())
    return r


# ---- Test 1: GUI subsystem PE ----
print("== Test 1: GUI PE ==")
gui_exe = os.path.join(VERIFY, "test_gui.exe")
run([
    "clang-cl", "-nologo", "-O2", os.path.join(VERIFY, "win.c"),
    f"-Fe:{gui_exe}", "-fuse-ld=lld",
    "-link", "-subsystem:windows",
    f"-libpath:{SDK_LIB}", f"-libpath:{MSVC_LIB}",
    "user32.lib", "kernel32.lib",
])
with open(gui_exe, "rb") as f:
    pe = f.read()
e_lfanew, = struct.unpack_from("<I", pe, 0x3C)
machine, = struct.unpack_from("<H", pe, e_lfanew + 4)
subsystem, = struct.unpack_from("<H", pe, e_lfanew + 24 + 68)
print(f"test_gui.exe: {len(pe)} bytes, Machine=0x{machine:X}, Subsystem={subsystem}")
assert machine == 0x8664, "not x64"
assert subsystem == 2, "not WINDOWS_GUI subsystem"

# ---- Test 2: zstd static link + alternatename ----
print("== Test 2: zstd link ==")
z_exe = os.path.join(VERIFY, "ztest.exe")
run([
    "clang-cl", "-nologo", "-O2", f"-I{ZSTD_INC}", os.path.join(VERIFY, "ztest.c"),
    f"-Fe:{z_exe}", "-fuse-ld=lld",
    "-link", "-subsystem:console",
    f"-libpath:{SDK_LIB}", f"-libpath:{MSVC_LIB}", f"-libpath:{ZSTD_LIB}",
    "-alternatename:___chkstk_ms=__chkstk",
    "libzstd_static.lib", "kernel32.lib",
])
r = subprocess.run([z_exe], capture_output=True, text=True)
print(r.stdout.strip())
assert r.returncode == 0
assert "match=1" in r.stdout, "zstd roundtrip failed"

print("ALL PASS")
