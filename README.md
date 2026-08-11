# Zygisk Gadget (Custom Linker) —— stealth frida-gadget 注入模块

> 📖 **使用教程**：见 [`使用教程.md`](使用教程.md)（部署/验证/连接/配置/常见问题）
> 成品下载：仓库 Releases 页（`zygisk_gadget_delivery.zip`）

> 适用：frida-gadget 17.9.1 (stealth) · Pixel 8 / Android 15 · KernelSU + Zygisk Next
> 验证日期：2026-07-27（真机通过）
> 相关公开参考：`SoyBeanMilkx/soLoader`（自定义 linker 源头）、`jiqiu2022/Zygisk-MyInjector`（mylinker 集成脚手架）

---

## 0. 背景：为什么要自定义 Linker

Android 10 起 linker namespace 隔离，`dlopen` 只能加载 app 自身 APK `lib/` 目录下的 SO，
**不能加载** `/data/data/<pkg>/libhhh.so` 这种动态拷贝的 frida gadget：

```
dlopen failed: library "/data/data/com.xff.launch/libhhh.so"
    needed or dlopened by "/data/app/.../lib/arm64/libxiaojia.so"
    is not accessible for the namespace "clns-4"
```

**解决思路**：在 Zygisk 模块（`libxiaojia.so`）里实现完整的手动 ELF 加载器（`mylinker`），
绕过系统 linker 直接把 gadget 映射进内存、解析重定位、调用构造函数。加载路径完全受控。

### 架构

```
libxiaojia.so (Zygisk 模块)
  └─ injection()
       └─ mylinker_load_library(gadget_path, javaVM)
            ├─ ElfReader::Open/Read            — 读 ELF 文件
            ├─ MemoryManager::ReserveAddressSpace — memfd:jit-cache 保留地址空间
            ├─ MemoryManager::LoadSegments     — 拷贝段到保留区
            ├─ MemoryManager::ProtectSegments  — 设置段权限 (r--/r-x/rw-)
            ├─ SoinfoManager::PrelinkImage     — 解析 .dynamic 段
            └─ Relocator::LinkImage            — 重定位 + 调用 init/init_array
```

---

## 1. 问题一：GOT 悬空指针（DLCLOSE 后段错误）

**现象**：gadget 加载后随机 SIGSEGV，崩溃地址指向 `libxiaojia.so` 已卸载区域。

**根因**：relocator 曾定义 `custom_dlsym` / `custom_dl_iterate_phdr` 静态函数并把地址写入
gadget GOT；Zygisk 在 `postAppSpecialize` 返回后 `DLCLOSE` 卸载 `libxiaojia.so` →
GOT 悬空。**铁律：自定义 linker 代码是临时的，gadget GOT 绝对不能指向 libxiaojia.so 内
任何地址。**

**修法**：删除拦截（`relocator.cpp` 已无 custom_dlsym 等），符号解析链：

1. 本 SO 内部（GNU hash / ELF hash）
2. DT_NEEDED 依赖库（`dlopen(RTLD_NOLOAD)` + `dlsym`）
3. 全局查（`dlsym(RTLD_DEFAULT, name)`）← `dlsym`/`dl_iterate_phdr` 走到这里，
   解析到 libc/libdl 真实地址（永不被卸载）

## 2. 问题二：DT_INIT 调用约定错误

Android linker 约定构造函数接收 `(argc, argv, envp)` 三参数，ARM64 下零参数调用会让
构造函数读到 X0-X2 残留垃圾值。修法：

```cpp
typedef void (*linker_ctor_function_t)(int, char**, char**);
extern char** environ;
((linker_ctor_function_t)si->init_func)(0, nullptr, environ);
// init_array 逐个同样调用
```

## 3. 问题三：SELinux execmod 拒绝可执行段

**根因**：memfd 属于 file-backed 页面，被写过（dirty）后再设 `PROT_EXEC` 触发
`FILE__EXECMOD` 检查，`untrusted_app` 无此权限；而 `MAP_ANONYMOUS` 只需
`process:execmem`（ART JIT 使用，必定有）。

| 映射类型 | 写后设 PROT_EXEC | 所需权限 | untrusted_app |
|----------|-----------------|---------|---------------|
| MAP_ANONYMOUS | execmem | process:execmem | ✅ |
| memfd (MAP_PRIVATE) | execmod | file:execmod | ❌ |

**修法**（`memory_manager.cpp` `ProtectSegments`）：可执行段 mprotect 失败时，
备份内容 → `mmap(MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE)` 同址替换 → 恢复内容 →
再 mprotect。代价：代码段在 maps 中显示 `[anon]`（数据/只读段仍 memfd 背衬）。

## 4. 问题四：detect_location 断言失败（核心阻塞）

```
Frida:ERROR:../subprojects/frida-core/lib/gadget/gadget.vala:744
  :frida_gadget_detect_location: assertion failed: (our_range != null)
```

**根因**：gadget 不在系统 linker 模块链 → `enumerate_modules` 找不到自身地址 →
`our_range` 为 null → assert 失败。`detect_location(Gum.MemoryRange? mapped_range)`
接受外部传入 range，但 Android 上 `frida_on_load` 硬编码传 NULL。

**修法：环境变量桥接**（跨 SO 传参，即用即清）：

- `elf_loader.cpp` 在 `LinkImage` 前：
  `setenv("FRIDA_GADGET_RANGE", "<base_hex>,<size_hex>", 1)`
- `gadget-glue.c` 的 `frida_on_load()`：`getenv` → 解析 base/size → `unsetenv` →
  传给 `frida_gadget_load(&range, ...)` → `detect_location` 跳过 enumerate，断言通过

（补丁见 `patch/gadget-glue.patch`）

## 5. 问题五：Gadget 配置文件找不到

**现象**：监听默认端口 27042，忽略配置的 14725。

**根因**：`mapped_range` 非空时 `detect_location` 回调立即返回，`our_path` 为 null →
`load_config(location)` 找不到旁边的 `.config.so`。

**修法**：同样环境变量桥接——`main.cpp` 读配置文件内容
`setenv("FRIDA_GADGET_CONFIG", 内容, 1)`，`frida_on_load` 中 `getenv` + `g_strdup` +
`unsetenv`，作为 `config_data` 传入 → `parse_config` 直接解析。

## 6. 改动文件汇总

| 文件 | 改动 |
|------|------|
| `module/jni/mylinker/relocator.cpp` | 符号解析链（无 GOT 拦截）+ DT_INIT 三参约定 |
| `module/jni/mylinker/memory_manager.cpp` | memfd:jit-cache 保留区 + execmod→匿名回退 |
| `module/jni/mylinker/elf_loader.cpp` | `LoadLibrary` 中设置 `FRIDA_GADGET_RANGE` |
| `module/jni/main.cpp` | `injection()` 设置 `FRIDA_GADGET_CONFIG` + 拷贝/清理 gadget 文件 |
| `subprojects/frida-core/lib/gadget/gadget-glue.c` | `frida_on_load()` 读取两个环境变量 |

## 7. 构建与部署

### 构建（Windows + WSL）

```powershell
# 1. Zygisk 模块（NDK 25.1）
$env:ANDROID_NDK_ROOT = "D:\AppData\Android\Sdk\ndk\25.1.8937393"
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
# 产出: module\libs\arm64-v8a\libxiaojia.so + dist\zygisk_gadget-v1.0.0.zip

# 2. frida gadget（WSL, NDK r29）—— 先在 frida 源码应用 patch/gadget-glue.patch
wsl -d AOSP-Ubuntu -- bash scripts/build_wsl.sh /root/frida-build/frida
# 产出: build/subprojects/frida-core/lib/gadget/frida-gadget.so
```

### 部署

```powershell
# 先 push 到 /data/local/tmp/，再 su -c cp（KernelSU su 有 namespace 隔离）
# cp -f 先删后建，规避权限问题
powershell -ExecutionPolicy Bypass -File scripts\deploy.ps1
# 或手动：
adb push frida-gadget.so /data/local/tmp/
adb shell "su -c 'cp -f /data/local/tmp/frida-gadget.so /data/adb/modules/zygisk_gadget/libgadget.so'"
adb shell "su -c 'cp -f /data/local/tmp/libxiaojia.so /data/adb/modules/zygisk_gadget/zygisk/arm64-v8a.so'"
adb reboot   # 必须重启，zygote 缓存旧 SO
```

### 配置

`/data/adb/zygisk_gadget/config.json`（**注意：不是 modules/ 下**，扁平格式，包名做顶层 key）：

```json
{
  "com.xff.launch": {
    "process": "com.xff.launch",
    "inject": true,
    "use_custom_linker": true,
    "delay_us": 0,
    "gadget_name": "libhhh.so",
    "gadget_config": "libhhh.config.so"
  }
}
```

gadget 侧配置文件放在 `/data/adb/modules/zygisk_gadget/libhhh.config.so` 的内容由模块
读取并注入环境变量（内容同标准 frida 配置，如 listen 14725）。

> 构建说明：`module/jni/zygisk.hpp` 为官方 API v5 头文件
> （topjohnwu/zygisk-module-sample，ISC 许可），模块用
> `REGISTER_ZYGISK_MODULE(ZygiskGadget)` 注册，`onLoad(Api*, JNIEnv*)` 中经
> `Api::getModuleDir()`（返回 fd）取模块目录。
>
> `pin_module`：Zygisk 在 postAppSpecialize 返回后 DLCLOSE 卸载模块 SO。注入在
> 独立线程执行（支持 delay_us），若 delay > 0 必须 `"pin_module": true`（dlopen 提升
> 引用计数阻止卸载）；delay=0 时可设 false 实现模块彻底无痕。

## 8. 验证标准

```
D [ZygiskGadget]: Frida-gadget injection thread start for com.xff.launch, gadget name: libhhh.so, usleep: 0, use_custom_linker: 1
D CustomLinker: Set FRIDA_GADGET_RANGE=73fa6a0000,18e9000 for detect_location
D CustomLinker: Relocation complete for libhhh.so
D CustomLinker: Calling 8 init_array functions
I Frida   : Listening on 0.0.0.0 TCP port 14725
D [ZygiskGadget]: Frida-gadget loaded via custom linker
D [ZygiskGadget]: Deleted gadget file: /data/data/com.xff.launch/libhhh.so
D [ZygiskGadget]: KPM: PING -> 0x4b504d48 (present)
```

验证项：detect_location 不崩 / 端口 14725 生效 / app 进程存活 / 无 tombstone /
`frida -H 127.0.0.1:14725` 可连接。

## 9. 踩坑记录

1. 配置路径是 `/data/adb/zygisk_gadget/config.json`，不在 modules/ 下
2. 配置 JSON 扁平格式，不是嵌套 apps
3. 模块替换必须 `adb reboot`（zygote 缓存旧 SO），force-stop 不够
4. KernelSU su 有 mount namespace 隔离 → 先 push tmp 再 su cp
5. 用 `cp -f`（先删后建）绕权限问题

## 10. 反检测协同

| 层级 | 机制 | 状态 |
|------|------|------|
| 加载层 | 自定义 ELF linker，不在系统 linker 模块链 | ✅ 本仓库 |
| 内存伪装 | memfd:jit-cache + **MAP_JIT**（VM_JIT 豁免 execmod，代码段不退化 [anon]，与 ART 行为一致） | ✅ 本仓库 |
| fd 无痕 | 加载完成后关闭 memfd fd（/proc/pid/fd 无 jit-cache 痕迹） | ✅ 本仓库 |
| 线程无痕 | gadget 线程名 patch 为 art.worker + `scripts/rename_threads.js` 双保险 | ✅ 本仓库 |
| 字符串无痕 | `scripts/obfuscate_gadget.py` 等长混淆 'frida-gadget' → 'art.worker.x'（.rodata，符号表不动） | ✅ 本仓库 |
| 环境变量无痕 | FRIDA_GADGET_* 即用即清（unsetenv 毫秒级） | ✅ 本仓库 |
| 磁盘无痕 | app 目录 gadget 写完即删 | ✅ 本仓库 |
| inode 一致性 | KPM ReportJitCacheSpoof | 🔧 需私有 KPM 内核模块 |
| 代码无痕 | KPM text_shadow | 🔧 需私有 KPM 内核模块 |
| 信号无痕 | FRIDA_STEALTH 跳过 gum_exceptor | 🔧 需私有编译补丁（官方源码无此宏） |
| 符号混淆 | frida_KjnwyG_ 式混淆 | 🔧 需私有补丁 |
| 进程无痕 | Zygisk DLCLOSE 卸载模块 SO（pin_module 默认 false；delay>0 自动 pin） | ✅ 本仓库 |

反检测评估结论：加载/内存/线程/字符串层已覆盖（见第 12 节审查记录）；
内核层（inode/code-shadow/信号）依赖私有 KPM 与 stealth 补丁，公开源码无法还原。
真机建议核查点：`cat /proc/<pid>/maps | grep -E "jit|anon"`、
`ls /proc/<pid>/task/*/comm | xargs cat`、`strings /proc/<pid>/mem 2>/dev/null | grep -ci frida`。

## 11. 已知限制

- 重定位目前支持 ABS64 / GLOB_DAT / JUMP_SLOT / RELATIVE / IRELATIVE / NONE。
  若 gadget 构建引入 TLS 类重定位（TLSDESC/TPREL），需在 `RelocateRela` 中补充
  处理（frida 17.9.1 stealth 默认构建不产生，已验证）。
- `GetSymbol` 的符号扫描以 st_name 越界为界，未记录符号总数（防御性上限 10 万）。
- 本仓库不含 KPM 内核模块本体；maps/inode 深度伪装需自行编写或参考
  `jiqiu2022/kpm-spore`（hidemap / injectHide / trace_maps）。

## 12. 代码审查修复记录（2026-08 实编译审查）

| 级别 | 问题 | 修复 |
|------|------|------|
| 致命 | GNU hash `buckets` 偏移误用 `>>1`（bloom 是 64 位 word，应 `*2`）；chain 起点误用 `gnu_hash[2]`（应为 `gnu_hash[0]`）→ 符号查错/崩溃 | `relocator.cpp` 按 abseil/musl 公式修正，编译产物无回归 |
| 严重 | `DT_NEEDED` 依赖 STRTAB 先到（单遍解析丢依赖）→ 依赖库符号解析链失效 | `soinfo_manager.cpp` 改两遍解析 |
| 严重 | postAppSpecialize 后读 `/data/adb/modules` 被 SELinux avc deny（app 沙箱）→ 注入必然失败 | 文件读取移到 preAppSpecialize（zygote 特权），post 线程只写 app 私有目录 |
| 中 | memfd fd 泄漏 → `/proc/pid/fd` 暴露 jit-cache 痕迹 | 加载成功后 `CloseReservedFd()`（映射不受影响） |
| 中 | `getModuleDir()` 在 onLoad 调用可能返回 -1（官方约定仅 pre[XXX]Specialize 可用）+ fd 泄漏 | 移到 preAppSpecialize 首行，用后 close |
| 低 | `strdup` 泄漏；重定位写入无越界防护 | `Cleanup` 释放；`RelocateRela` 加映射区边界检查 |
| 高 | 代码段 execmod 回退成 `[anon]`（maps 指纹弱化） | **MAP_JIT**（0x8000，与 ART jit-cache 同机制，VM_JIT 豁免 execmod），失败自动回退原路径 |
| 高 | 线程名 `frida-gadget` 暴露（/proc/self/task/comm） | gadget-glue.c patch 为 `art.worker` + rename_threads.js 双保险 |
| 中 | 二进制含 `frida-gadget` 字符串（socket 名/raw 库名/错误消息） | obfuscate_gadget.py 等长混淆（.rodata 3 处；.dynstr SONAME 保留不破坏链接） |
| 中 | pin_module 默认 true 违背"进程无痕" | 默认 false；delay_us>0 自动 pin |
