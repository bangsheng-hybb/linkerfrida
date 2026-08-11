#include "memory_manager.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>

#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "CustomLinker", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "CustomLinker", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "CustomLinker", __VA_ARGS__)

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define PAGE_START(addr) ((addr) & ~(ElfW(Addr))(PAGE_SIZE - 1))
#define PAGE_END(addr) (((addr) + PAGE_SIZE - 1) & ~(ElfW(Addr))(PAGE_SIZE - 1))

// MAP_JIT: Android 10+ (API 29)，bionic sys/mman.h 中 android-26 平台无定义。
// 语义：映射带 VM_JIT 标志（与 ART 的 jit-cache 一致），内核豁免 execmod 检查，
// 允许写后转可执行。使用 MAP_JIT 后代码段无需退化成匿名页，保持 memfd 伪装。
#ifndef MAP_JIT
#define MAP_JIT 0x8000
#endif

// 老 NDK 可能没有 memfd_create 包装，直接用 syscall
#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif

static int memfd_create_compat(const char* name, unsigned int flags) {
    return (int)syscall(__NR_memfd_create, name, flags);
}

// 记录保留区状态（模块内全局，加载期间有效）
static int g_reserved_fd = -1;
static size_t g_reserved_size = 0;

namespace mylinker {

ElfW(Addr) MemoryManager::ReserveAddressSpace(size_t size) {
    size = PAGE_END(size);
    if (size == 0) return 0;

    // memfd:jit-cache —— maps 里显示为 ART JIT 代码缓存
    int mfd = memfd_create_compat("jit-cache", 0);
    if (mfd < 0) {
        LOGE("memfd_create jit-cache failed: %s", strerror(errno));
        return 0;
    }
    if (ftruncate(mfd, (off_t)size) != 0) {
        LOGE("ftruncate failed: %s", strerror(errno));
        close(mfd);
        return 0;
    }

    // 先尝试 MAP_JIT（与 ART jit-cache 完全一致：VM_JIT 豁免 execmod，
    // 写后设 PROT_EXEC 无需 execmem/execmod 权限，保持 memfd 伪装）；
    // 老内核不支持则回退普通 MAP_PRIVATE（走 execmod→匿名回退路径）。
    void* base = mmap(nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_JIT, mfd, 0);
    if (base == MAP_FAILED) {
        base = mmap(nullptr, size, PROT_NONE, MAP_PRIVATE, mfd, 0);
        if (base == MAP_FAILED) {
            LOGE("mmap reserve failed: %s", strerror(errno));
            close(mfd);
            return 0;
        }
    }

    // 记录 fd 以便后续替换映射后关闭；以全局形式保存一份供 LoadSegments 使用
    g_reserved_fd = mfd;
    g_reserved_size = size;
    LOGD("Reserved %zu bytes via memfd:jit-cache at %p", size, base);
    return (ElfW(Addr))base;
}

bool MemoryManager::LoadSegments(ElfW(Addr) load_bias,
                                 const ElfW(Phdr)* phdr_table,
                                 size_t phdr_num,
                                 int fd,
                                 off_t file_offset) {
    (void)file_offset; // 保留：段文件偏移固定从 p_offset 读取
    if (g_reserved_fd < 0) {
        LOGE("LoadSegments: no reserved mapping");
        return false;
    }
    for (size_t i = 0; i < phdr_num; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table[i];
        if (phdr->p_type != PT_LOAD) continue;

        ElfW(Addr) seg_page_start = PAGE_START(phdr->p_vaddr + load_bias);
        ElfW(Addr) seg_page_end = PAGE_END(phdr->p_vaddr + phdr->p_memsz + load_bias);
        size_t seg_size = seg_page_end - seg_page_start;

        // 先解锁写权限
        if (mprotect((void*)seg_page_start, seg_size, PROT_READ | PROT_WRITE) != 0) {
            LOGE("mprotect rw failed for segment %zu: %s", i, strerror(errno));
            return false;
        }

        // 清零 .bss 区（memsz > filesz 部分）
        memset((void*)seg_page_start, 0, seg_size);

        // 拷贝 filesz 部分（按 p_offset 从文件读取）
        off_t file_off = phdr->p_offset;
        size_t copy_size = phdr->p_filesz;
        if (copy_size > 0) {
            ssize_t n = pread(fd, (void*)seg_page_start, copy_size, file_off);
            if (n != (ssize_t)copy_size) {
                LOGE("pread segment %zu failed: %zd != %zu (%s)",
                     i, n, copy_size, strerror(errno));
                return false;
            }
        }
    }
    return true;
}

bool MemoryManager::ProtectSegments(ElfW(Addr) load_bias,
                                    const ElfW(Phdr)* phdr_table,
                                    size_t phdr_num) {
    for (size_t i = 0; i < phdr_num; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table[i];
        if (phdr->p_type != PT_LOAD) continue;

        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias;
        ElfW(Addr) seg_page_start = PAGE_START(seg_start);
        ElfW(Addr) seg_page_end = PAGE_END(seg_start + phdr->p_memsz);
        size_t seg_size = seg_page_end - seg_page_start;
        int prot = 0;
        if (phdr->p_flags & PF_R) prot |= PROT_READ;
        if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

        if (mprotect((void*)seg_page_start, seg_size, prot) == 0)
            continue;

        // 非可执行段失败是真错误
        if (!(prot & PROT_EXEC)) {
            LOGE("Cannot protect segment %zu: %s", i, strerror(errno));
            return false;
        }

        // 可执行段失败 → SELinux execmod（memfd 页面被写过后不能再设 X），转匿名
        LOGD("mprotect exec failed (SELinux execmod), converting to anonymous");

        void* backup = malloc(seg_size);
        if (backup == nullptr) {
            LOGE("malloc backup failed");
            return false;
        }
        memcpy(backup, (void*)seg_page_start, seg_size);

        // MAP_FIXED + MAP_ANONYMOUS 替换同一地址的 memfd 映射。
        // 匿名页设 PROT_EXEC 只需 process:execmem（ART JIT 使用，untrusted_app 必有）
        void* anon = mmap((void*)seg_page_start, seg_size,
                          PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (anon == MAP_FAILED) {
            LOGE("MAP_FIXED anon replacement failed: %s", strerror(errno));
            free(backup);
            return false;
        }

        memcpy(anon, backup, seg_size);
        free(backup);

        if (mprotect(anon, seg_size, prot) != 0) {
            LOGE("mprotect anon exec failed: %s", strerror(errno));
            return false;
        }
    }
    return true;
}

void MemoryManager::ReleaseReserved(ElfW(Addr) base, size_t size) {
    if (base != 0 && size != 0) {
        munmap((void*)base, size);
    }
    CloseReservedFd();
}

void MemoryManager::CloseReservedFd() {
    if (g_reserved_fd >= 0) {
        close(g_reserved_fd);
        g_reserved_fd = -1;
    }
    g_reserved_size = 0;
}

} // namespace mylinker
