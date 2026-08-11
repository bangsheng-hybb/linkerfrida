#pragma once

#include <sys/types.h>

#include "elf_compat.h"

namespace mylinker {

// 内存管理器：memfd:jit-cache 保留地址空间 + 段拷贝 + 权限设置。
// memfd 背衬使 /proc/pid/maps 呈现为 ART JIT 缓存而非匿名可执行段指纹。
class MemoryManager {
public:
    // 用 memfd_create("jit-cache") + mmap 保留一块可执行地址空间，
    // 返回保留区基址（已按页对齐）；失败返回 0。
    static ElfW(Addr) ReserveAddressSpace(size_t size);

    // 将 ELF 段数据拷贝进保留区（先只读+写权限拷贝，再统一设权限）。
    static bool LoadSegments(ElfW(Addr) load_bias,
                             const ElfW(Phdr)* phdr_table,
                             size_t phdr_num,
                             int fd,
                             off_t file_offset);

    // 设置各 PT_LOAD 段权限 (r-- / r-x / rw-)。
    // 可执行段 mprotect 失败（SELinux execmod 拒绝）时，
    // 自动 MAP_FIXED|MAP_ANONYMOUS 替换为匿名页后重试（匿名页只需 execmem）。
    static bool ProtectSegments(ElfW(Addr) load_bias,
                                const ElfW(Phdr)* phdr_table,
                                size_t phdr_num);

    // 释放整个保留区。
    static void ReleaseReserved(ElfW(Addr) base, size_t size);

    // 加载完成后关闭 memfd fd（映射不受影响）。
    // 泄漏的 fd 会出现在 /proc/pid/fd，且暴露 memfd:jit-cache 痕迹。
    static void CloseReservedFd();
};

} // namespace mylinker
