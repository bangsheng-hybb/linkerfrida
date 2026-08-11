# Build Zygisk module (libxiaojia.so) - Windows / NDK 25.1
# Usage: powershell -ExecutionPolicy Bypass -File build.ps1

$ErrorActionPreference = "Stop"

# --- Config ---
$NDK = $env:ANDROID_NDK_ROOT
if (-not $NDK) {
    # 自动探测常见位置
    $candidates = @(
        "D:\AppData\Android\Sdk\ndk\25.1.8937393",
        "D:\ai\android\android-ndk-r27c",
        "$env:LOCALAPPDATA\Android\Sdk\ndk"
    )
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "ndk-build.cmd")) { $NDK = $c; break }
    }
    if (-not $NDK -and (Test-Path "$env:LOCALAPPDATA\Android\Sdk\ndk")) {
        # 有多个版本时取最新的
        $NDK = Get-ChildItem "$env:LOCALAPPDATA\Android\Sdk\ndk" -Directory |
               Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
}
$SRC = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$MODULE = Join-Path $SRC "module"

if (-not (Test-Path (Join-Path $NDK "ndk-build.cmd"))) {
    Write-Error "NDK not found at $NDK. Set ANDROID_NDK_ROOT."
    exit 1
}

Write-Host "=== Building Zygisk module with NDK $NDK ==="
& (Join-Path $NDK "ndk-build.cmd") -C $MODULE -j8
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$out = Join-Path $MODULE "libs\arm64-v8a\libxiaojia.so"
if (-not (Test-Path $out)) {
    Write-Error "Build produced no output: $out"
    exit 1
}

# Copy into zygisk layout
Copy-Item $out (Join-Path $MODULE "zygisk\arm64-v8a.so") -Force
Write-Host "OK: $out -> module\zygisk\arm64-v8a.so"

# --- Package into a flashable zip ---
$dist = Join-Path $SRC "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$zip = Join-Path $dist "zygisk_gadget-v1.0.0.zip"
if (Test-Path $zip) { Remove-Item $zip }

$staging = Join-Path $env:TEMP "zygisk_gadget_pkg"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $staging "zygisk") | Out-Null

Copy-Item (Join-Path $MODULE "module.prop") $staging
Copy-Item (Join-Path $MODULE "zygisk\arm64-v8a.so") (Join-Path $staging "zygisk\")
Copy-Item (Join-Path $MODULE "libs\arm64-v8a\libxiaojia.so") (Join-Path $staging "zygisk\arm64-v8a.so") -Force

# customize.sh: minimal installer
@'
SKIPMOUNT=false
PROPFILE=false
POSTFSDATA=false
LATESTARTSERVICE=false

ui_print "- Installing Zygisk Gadget (custom linker)"
'@ | Set-Content (Join-Path $staging "customize.sh") -Encoding UTF8

Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zip -Force
Write-Host "Package: $zip"
