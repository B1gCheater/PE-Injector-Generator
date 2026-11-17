#!/bin/bash
# 克隆 blueprint §13 参考仓库到 temp/ 下，走本机 v2ray socks5 代理
set -u
cd /d/project/PE-Injector-Generator/temp || exit 1
PROXY_ARGS="-c http.proxy=socks5h://127.0.0.1:2080 -c https.proxy=socks5h://127.0.0.1:2080"

repos=(
  frank2/pe-loader-example
  buzzer-re/BulletTrain
  Fatmike-GH/PELoader
  stephenfewer/ReflectiveDLLInjection
  dismantl/ImprovedReflectiveDLLInjection
  monoxgas/sRDI
  fancycode/MemoryModule
  hasherezade/pe_to_shellcode
  TheCruZ/Simple-Manual-Map-Injector
  DarthTon/Blackbone
  Eric-Ant/SelfInjectPE
)

fail=0
for r in "${repos[@]}"; do
  name=$(basename "$r")
  if [ -d "$name" ]; then
    echo "SKIP  $name (already exists)"
    continue
  fi
  echo "CLONE $r ..."
  if git $PROXY_ARGS clone --depth 1 --quiet "https://github.com/$r.git" "$name"; then
    echo "OK    $name"
  else
    echo "FAIL  $name"
    fail=$((fail+1))
  fi
done

# zstd 源码：固定 v1.5.7（与本机预编译库同版本）
if [ -d "zstd" ]; then
  echo "SKIP  zstd (already exists)"
else
  echo "CLONE facebook/zstd (v1.5.7) ..."
  if git $PROXY_ARGS clone --depth 1 --branch v1.5.7 --quiet https://github.com/facebook/zstd.git zstd; then
    echo "OK    zstd"
  else
    echo "FAIL  zstd"
    fail=$((fail+1))
  fi
fi

echo "=== DONE (failures: $fail) ==="
