# One-shot deploy for Tom&Jerry (com.netease.TomJerry)
# 一键部署：push 模块 + gadget + 写配置 + 重启
# Usage: powershell -ExecutionPolicy Bypass -File deploy_all.ps1

$ErrorActionPreference = "Stop"
$ADB = "D:\ai\android\platform-tools\adb.exe"
$SRC = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)  # zygisk_gadget_src
$REL = Join-Path $SRC "release"

# helper: run a shell command via su
function adb_su([string]$cmd) {
    & $ADB shell "su -c '$cmd'"
}

# 0. 检查设备
$devices = & $ADB devices | Select-String -Pattern "\tdevice$"
if (-not $devices) {
    Write-Host "No device connected!" -ForegroundColor Red
    exit 1
}
Write-Host "=== Device: $($devices.Line.Trim()) ==="

# 1. push 到 /data/local/tmp（KernelSU su 有 namespace 隔离，必须先 push 再 su cp）
& $ADB push (Join-Path $SRC "module\libs\arm64-v8a\libxiaojia.so") /data/local/tmp/libxiaojia.so
& $ADB push (Join-Path $SRC "module\libgadget.so") /data/local/tmp/frida-gadget.so
& $ADB push (Join-Path $REL "config.json") /data/local/tmp/config.json
& $ADB push (Join-Path $REL "libhhh.config.so") /data/local/tmp/libhhh.config.so

# 2. 安装模块 + 写配置（cp -f 先删后建，绕权限问题）
adb_su "mkdir -p /data/adb/modules/zygisk_gadget/zygisk; cp -f /data/local/tmp/libxiaojia.so /data/adb/modules/zygisk_gadget/zygisk/arm64-v8a.so; cp -f /data/local/tmp/frida-gadget.so /data/adb/modules/zygisk_gadget/libgadget.so; chmod 755 /data/adb/modules/zygisk_gadget/zygisk/arm64-v8a.so; cp -f /data/local/tmp/libhhh.config.so /data/adb/modules/zygisk_gadget/libhhh.config.so; mkdir -p /data/adb/zygisk_gadget; cp -f /data/local/tmp/config.json /data/adb/zygisk_gadget/config.json; echo DEPLOY_OK"
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "=== Files installed ===" -ForegroundColor Green
adb_su "ls -la /data/adb/modules/zygisk_gadget /data/adb/modules/zygisk_gadget/zygisk /data/adb/zygisk_gadget"
Write-Host ""
Write-Host "=== Rebooting (zygisk needs zygote reload) ==="
& $ADB reboot
& $ADB wait-for-device
Start-Sleep -Seconds 5
Write-Host "=== Done. Watch logs: ===" -ForegroundColor Green
Write-Host "  adb logcat -s ZygiskGadget CustomLinker Frida"
Write-Host "  (open the game, expect: Frida: Listening on 0.0.0.0 TCP port 14725)"
Write-Host "  frida -H 127.0.0.1:14725 -n Gadget"
