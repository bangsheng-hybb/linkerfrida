#!/bin/bash
# Build custom frida-gadget 17.9.1 (android-arm64) with FRIDA_GADGET_RANGE/CONFIG bridge
# Tested: WSL2 Ubuntu 22.04.5, NDK r29, Node 20, 2026-08-10
#
# One-time environment setup (WSL, as root):
#   apt-get install -y git curl xz-utils unzip build-essential python3 python3-pip python3-venv ninja-build
#   pip3 install meson
#   # NDK r29 -> /opt/android-ndk-r29 (dl.google.com 被墙时用腾讯镜像:
#   #   https://mirrors.cloud.tencent.com/AndroidSDK/android-ndk-r29-linux.zip)
#   # Node 20 -> /opt/node (https://npmmirror.com/mirrors/node/v20.19.0/node-v20.19.0-linux-x64.tar.xz)
#   ln -sf /opt/node/bin/node /usr/local/bin/node

set -e

export ANDROID_NDK_HOME=/opt/android-ndk-r29
export ANDROID_NDK_ROOT=/opt/android-ndk-r29
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/node/bin

FRIDA_SRC="${1:-/root/frida-build/frida}"
OUT_BASE="${2:-/root/frida-build}"
cd "$FRIDA_SRC"

# 1. Patch gadget-glue.c (idempotent)
PATCH_SCRIPT=/root/patch_gadget_glue.py
if ! grep -q FRIDA_GADGET_RANGE subprojects/frida-core/lib/gadget/gadget-glue.c; then
    echo "Applying gadget-glue bridge patch..."
    python3 "$PATCH_SCRIPT"
fi

# 2. Configure (only needs to be done once; re-run is cheap)
if [ ! -f build/build.ninja ]; then
    ./configure --host=android-arm64 --enable-gadget --disable-server \
        --disable-frida-tools --disable-inject --disable-frida-python > /tmp/configure.log 2>&1 \
        || { tail -40 /tmp/configure.log; exit 1; }
fi

# 3. Build
cd build
/root/frida-build/frida/deps/toolchain-linux-x86_64/bin/ninja \
    subprojects/frida-core/lib/gadget/frida-gadget.so > /tmp/ninja_build.log 2>&1 \
    || { tail -60 /tmp/ninja_build.log; exit 1; }

OUT=subprojects/frida-core/lib/gadget/frida-gadget.so
echo "=== gadget built: $PWD/$OUT ==="
ls -lh "$OUT"
echo "=== bridge strings present: ==="
strings "$OUT" | grep -c FRIDA_GADGET
