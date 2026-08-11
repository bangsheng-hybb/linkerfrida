# Deploy to device - Windows
# Usage: powershell -ExecutionPolicy Bypass -File deploy.ps1

$ErrorActionPreference = "Stop"

$SRC = Split-Path -Parent $MyInvocation.MyCommand.Path
$MODULE = Join-Path $SRC "module"

# 1. Push to tmp (KernelSU su 有 mount namespace 隔离，必须先 push 再 su cp)
adb push (Join-Path $MODULE "libs\arm64-v8a\libxiaojia.so") /data/local/tmp/
adb push (Join-Path $MODULE "zygisk\arm64-v8a.so") /data/local/tmp/libxiaojia.so
$gadget = $args[0]
if (-not $gadget) {
    $gadget = Join-Path $SRC "..\frida-gadget.so"  # 或自己指定路径
}
if (Test-Path $gadget) {
    adb push $gadget /data/local/tmp/frida-gadget.so
} else {
    Write-Host "gadget not found at $gadget, skipping (remember to push it)" -ForegroundColor Yellow
}

# 2. su -c cp（cp -f 避免权限问题）
adb shell "su -c 'cp -f /data/local/tmp/libxiaojia.so /data/adb/modules/zygisk_gadget/zygisk/arm64-v8a.so && cp -f /data/local/tmp/frida-gadget.so /data/adb/modules/zygisk_gadget/libgadget.so && chmod 755 /data/adb/modules/zygisk_gadget/zygisk/arm64-v8a.so'"

# 3. 配置写到持久化路径 /data/adb/zygisk_gadget/config.json（不是 modules/ 下）
adb shell "su -c 'mkdir -p /data/adb/zygisk_gadget'"
$cfg = Join-Path $MODULE "config.json.example"
adb push $cfg /data/local/tmp/config.json
adb shell "su -c 'cp -f /data/local/tmp/config.json /data/adb/zygisk_gadget/config.json'"

# 4. 重启（zygisk 模块替换必须重启，zygote 缓存了旧 SO）
Write-Host "=== Rebooting device (zygisk needs zygote reload) ==="
adb reboot
adb wait-for-device
Write-Host "=== Done. Check: adb logcat -s ZygiskGadget CustomLinker Frida ==="
