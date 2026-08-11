#include "elf_loader.h"

#include <dlfcn.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>

#include <android/log.h>

#include "elf_reader.h"
#include "memory_manager.h"
#include "soinfo_manager.h"
#include "relocator.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "CustomLinker", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "CustomLinker", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "CustomLinker", __VA_ARGS__)

namespace mylinker {

// mylinker 模块内符号，供 Zygisk 模块调用（见 main.cpp）
extern "C" __attribute__((visibility("default"))) {

bool mylinker_load_library(const char* library_path, void* java_vm);
void* mylinker_get_symbol(const char* symbol_name);
void mylinker_cleanup();

} // extern "C"

static ElfLoader g_loader;

bool ElfLoader::LoadLibrary(const char* library_path, void* java_vm) {
    (void)java_vm; // frida 环境变量桥接已覆盖需求，无需 JNIEnv

    // 1. 读 ELF（解析映射在 Close 前有效）
    ElfReader reader;
    if (!reader.Open(library_path)) {
        return false;
    }

    // 2. 拷贝 phdr 到堆（reader.Close 后解析映射失效，soinfo 仍需使用）
    size_t phdr_bytes = reader.phdr_num() * sizeof(ElfW(Phdr));
    ElfW(Phdr)* phdr_copy = (ElfW(Phdr)*)malloc(phdr_bytes);
    if (phdr_copy == nullptr) {
        reader.Close();
        return false;
    }
    memcpy(phdr_copy, reader.phdr(), phdr_bytes);

    // 3. 保留地址空间（memfd:jit-cache 背衬，maps 伪装 ART JIT 缓存）
    size_t reserve_size = ElfReader::GetReservedSize(phdr_copy, reader.phdr_num());
    ElfW(Addr) base = MemoryManager::ReserveAddressSpace(reserve_size);
    if (base == 0) {
        free(phdr_copy);
        reader.Close();
        return false;
    }

    // 4. 拷贝段到保留区
    if (!MemoryManager::LoadSegments(base, phdr_copy, reader.phdr_num(),
                                     reader.fd(), 0)) {
        MemoryManager::ReleaseReserved(base, reserve_size);
        free(phdr_copy);
        reader.Close();
        return false;
    }

    // 5. 设置段权限（可执行段 execmod 拒绝时自动转匿名页）
    if (!MemoryManager::ProtectSegments(base, phdr_copy, reader.phdr_num())) {
        MemoryManager::ReleaseReserved(base, reserve_size);
        free(phdr_copy);
        reader.Close();
        return false;
    }
    reader.Close();

    // 6. 组装 soinfo 并解析 .dynamic
    Soinfo* si = new Soinfo();
    si->base = base;
    si->size = reserve_size;
    si->phdr = phdr_copy;
    si->phnum = reader.phdr_num();
    si->name = strdup(library_path);
    (void)si->name;

    if (!SoinfoManager::PrelinkImage(si)) {
        LOGE("PrelinkImage failed for %s", library_path);
        MemoryManager::ReleaseReserved(base, reserve_size);
        free((void*)si->name);
        delete si;
        return false;
    }

    // 7. 环境变量桥接：gadget 的 frida_on_load 需要自身内存范围
    //    （修复 detect_location 断言 our_range != null，见技术文档问题四）
    {
        char range_buf[48];
        snprintf(range_buf, sizeof(range_buf), "%llx,%llx",
                 (unsigned long long)si->base,
                 (unsigned long long)si->size);
        setenv("FRIDA_GADGET_RANGE", range_buf, 1);
        LOGD("Set FRIDA_GADGET_RANGE=%s for detect_location", range_buf);
    }

    // 8. 重定位 + 调用 init/init_array（frida_on_load 在此执行并消费环境变量）
    if (!Relocator::LinkImage(si)) {
        LOGE("LinkImage failed for %s", library_path);
        unsetenv("FRIDA_GADGET_RANGE");
        MemoryManager::ReleaseReserved(base, reserve_size);
        free((void*)si->name);
        delete si;
        return false;
    }
    unsetenv("FRIDA_GADGET_RANGE"); // 构造函数已消费，立即清除不泄露

    // 关闭 memfd fd（映射保持有效，但 /proc/pid/fd 不再暴露 jit-cache）
    MemoryManager::CloseReservedFd();

    loaded_si_ = si;
    LOGI("Loaded %s via custom linker (base=%p size=%zu)",
         library_path, (void*)base, reserve_size);
    return true;
}

void* ElfLoader::GetSymbol(const char* symbol_name) {
    if (loaded_si_ == nullptr) return nullptr;
    // 先全局查（libc 等常驻库）
    void* addr = dlsym(RTLD_DEFAULT, symbol_name);
    if (addr != nullptr) return addr;
    // 兜底：内部符号表扫描（以 st_name 越界为终止条件，防御性上限）
    const char* str = loaded_si_->strtab;
    size_t str_size = loaded_si_->strtab_size;
    for (size_t i = 0; i < 100000; ++i) {
        const ElfW(Sym)* sym = &loaded_si_->symtab[i];
        if (sym->st_name >= str_size) break;
        if (strcmp(str + sym->st_name, symbol_name) == 0 && sym->st_value != 0) {
            return (void*)(loaded_si_->base + sym->st_value);
        }
    }
    return nullptr;
}

void ElfLoader::Cleanup() {
    if (loaded_si_ != nullptr) {
        MemoryManager::ReleaseReserved(loaded_si_->base, loaded_si_->size);
        if (loaded_si_->name != nullptr) {
            free((void*)loaded_si_->name);
        }
        delete loaded_si_;
        loaded_si_ = nullptr;
    }
}

// ---------- C 接口 ----------

__attribute__((visibility("default")))
bool mylinker_load_library(const char* library_path, void* java_vm) {
    return g_loader.LoadLibrary(library_path, java_vm);
}

__attribute__((visibility("default")))
void* mylinker_get_symbol(const char* symbol_name) {
    return g_loader.GetSymbol(symbol_name);
}

__attribute__((visibility("default")))
void mylinker_cleanup() {
    g_loader.Cleanup();
}

} // namespace mylinker
