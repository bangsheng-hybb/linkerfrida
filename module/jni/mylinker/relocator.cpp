#include "relocator.h"

#include <dlfcn.h>
#include <link.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "CustomLinker", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "CustomLinker", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "CustomLinker", __VA_ARGS__)

extern char** environ;

namespace mylinker {

// ---------- ELF hash / GNU hash 查找 ----------

static uint32_t elf_hash_impl(const char* name) {
    uint32_t h = 0;
    while (*name) {
        h = (h << 4) + (unsigned char)*name++;
        uint32_t g = h & 0xf0000000;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static uint32_t gnu_hash_impl(const char* name) {
    uint32_t h = 5381;
    while (*name) {
        h = h * 33 + (unsigned char)*name++;
    }
    return h;
}

// 在 soinfo 内部符号表中查找（GNU hash 优先，ELF hash 兜底）
static const ElfW(Sym)* FindSymbolInternal(Soinfo* si, const char* name) {
    if (si == nullptr || si->symtab == nullptr || si->strtab == nullptr)
        return nullptr;

    if (si->gnu_hash != nullptr) {
        // GNU hash 布局：nbuckets | symoffset | bloom_size | bloom_shift |
        // bloom[bloom_size]（ELFCLASS 宽度 word）| buckets[nbuckets] | chain[]
        // bloom 按 64 位 word 计，转 uint32 偏移需 *2（arm64）
        const uint32_t* buckets =
            si->gnu_hash + 4 + si->gnu_hash[2] * (sizeof(ElfW(Addr)) / sizeof(uint32_t));
        // chain 起始 = buckets + nbuckets - symoffset
        const uint32_t* chain = buckets + si->gnu_hash[0] - si->gnu_hash[1];
        uint32_t hash = gnu_hash_impl(name);
        uint32_t idx = buckets[hash % si->gnu_hash[0]];
        if (idx == 0) return nullptr;
        while (true) {
            const ElfW(Sym)* sym = &si->symtab[idx];
            if (sym->st_name < si->strtab_size &&
                strcmp(si->strtab + sym->st_name, name) == 0) {
                return sym;
            }
            // 链尾判定：chain 条目最低位为 1 表示哈希链结束
            if ((chain[idx - si->gnu_hash[1]] & 1) == 1) break;
            idx++;
        }
        return nullptr;
    }

    if (si->elf_hash != nullptr) {
        uint32_t hash = elf_hash_impl(name);
        uint32_t nbucket = si->elf_hash[0];
        const uint32_t* buckets = &si->elf_hash[2];
        const uint32_t* chains = buckets + nbucket;
        for (uint32_t i = buckets[hash % nbucket]; i != 0; i = chains[i]) {
            const ElfW(Sym)* sym = &si->symtab[i];
            if (sym->st_name < si->strtab_size &&
                strcmp(si->strtab + sym->st_name, name) == 0) {
                return sym;
            }
        }
        return nullptr;
    }

    // 没有哈希表：线性扫描（不应该出现，防御性）
    size_t max_sym = 0;
    // 用 hash 后的符号总数粗略上界：从 rela 符号索引看不出总数，
    // 退化为扫描 0..strtab 无法确定边界，直接返回 null
    (void)max_sym;
    return nullptr;
}

// ---------- 符号解析链 ----------
// 1. 本 SO 内部（GNU hash / ELF hash）
// 2. DT_NEEDED 依赖库（dlopen(RTLD_NOLOAD) + dlsym）
// 3. 全局查（dlsym(RTLD_DEFAULT, name)）
//
// 铁律：自定义 linker 代码（libxiaojia.so）会被 Zygisk DLCLOSE 卸载，
// gadget 的 GOT 绝对不能指向 libxiaojia.so 内任何地址。
// 所有外部符号必须解析到永久存在的系统库 —— 因此这里不拦截任何符号，
// dlsym / dl_iterate_phdr 等一律走第 3 步解析到 libc/libdl 真实地址。
static ElfW(Addr) FindSymbolAddress(Soinfo* si, const char* name) {
    // 1. 本 SO 内部
    const ElfW(Sym)* sym = FindSymbolInternal(si, name);
    if (sym != nullptr && sym->st_value != 0) {
        return si->base + sym->st_value;
    }

    // 2. DT_NEEDED 依赖库（已加载的）
    for (const auto& lib : si->needed_libs) {
        void* h = dlopen(lib.c_str(), RTLD_NOLOAD);
        if (h != nullptr) {
            void* addr = dlsym(h, name);
            dlclose(h);
            if (addr != nullptr) {
                return (ElfW(Addr))addr;
            }
        }
    }

    // 3. 全局查（libc/libdl 等常驻库）
    void* addr = dlsym(RTLD_DEFAULT, name);
    if (addr != nullptr) {
        return (ElfW(Addr))addr;
    }

    LOGD("FindSymbolAddress: unresolved symbol %s", name);
    return 0;
}

// ---------- 重定位 ----------

static bool RelocateRela(Soinfo* si, const ElfW(Rela)* rela, size_t count, bool is_plt) {
    for (size_t i = 0; i < count; ++i) {
        const ElfW(Rela)* r = &rela[i];
        ElfW(Addr) reloc_addr = si->base + r->r_offset;
        ElfW(Word) type = ELF64_R_TYPE(r->r_info);
        ElfW(Word) sym_idx = ELF64_R_SYM(r->r_info);

        // 防御：重定位目标必须落在映射区内（防畸形 ELF 越界写）
        if (reloc_addr < si->base || reloc_addr + sizeof(ElfW(Addr)) > si->base + si->size) {
            LOGE("relocation target out of range: %llx", (unsigned long long)reloc_addr);
            return false;
        }

        ElfW(Addr) sym_addr = 0;
        if (sym_idx != 0) {
            const ElfW(Sym)* sym = &si->symtab[sym_idx];
            if (sym->st_name < si->strtab_size) {
                const char* name = si->strtab + sym->st_name;
                sym_addr = FindSymbolAddress(si, name);
                if (sym_addr == 0 && name[0] != '\0') {
                    // 弱符号允许未解析
                    if ((sym->st_info & 0xf) == STB_WEAK) {
                        sym_addr = 0;
                    } else {
                        LOGE("relocation failed for %s (sym=%u, type=%u)",
                             name, sym_idx, type);
                        return false;
                    }
                }
            }
        }

        ElfW(Addr) addend = r->r_addend;
        switch (type) {
            case R_AARCH64_ABS64:
                *(ElfW(Addr)*)reloc_addr = sym_addr + addend;
                break;
            case R_AARCH64_GLOB_DAT:
            case R_AARCH64_JUMP_SLOT:
                *(ElfW(Addr)*)reloc_addr = sym_addr + addend;
                break;
            case R_AARCH64_RELATIVE:
                *(ElfW(Addr)*)reloc_addr = si->base + addend;
                break;
            case R_AARCH64_IRELATIVE: {
                // 运行时选择器：调用返回真实地址
                typedef ElfW(Addr) (*resolver_t)();
                resolver_t resolver = (resolver_t)(si->base + addend);
                *(ElfW(Addr)*)reloc_addr = resolver();
                break;
            }
            case R_AARCH64_NONE:
                break;
            default:
                LOGE("unsupported relocation type %u%s", type, is_plt ? " (plt)" : "");
                return false;
        }
    }
    return true;
}

// ---------- 构造函数 ----------

// Android linker 标准调用约定：init/init_array 接收 (argc, argv, envp)
typedef void (*linker_ctor_function_t)(int, char**, char**);

static void CallCtor(ElfW(Addr) func) {
    if (func == 0) return;
    linker_ctor_function_t f = (linker_ctor_function_t)func;
    f(0, nullptr, environ);
}

bool Relocator::LinkImage(Soinfo* si) {
    // 1. PLT/GOT 重定位
    if (si->plt_rela != nullptr && !RelocateRela(si, si->plt_rela, si->plt_rela_count, true)) {
        LOGE("PLT relocation failed for %s", si->name ? si->name : "?");
        return false;
    }
    // 2. 非 PLT 重定位
    if (si->rela != nullptr && !RelocateRela(si, si->rela, si->rela_count, false)) {
        LOGE("relocation failed for %s", si->name ? si->name : "?");
        return false;
    }
    LOGI("Relocation complete for %s", si->name ? si->name : "?");

    // 3. DT_INIT
    if (si->init_func != 0) {
        LOGD("Calling init at %p", (void*)si->init_func);
        CallCtor(si->init_func);
    }

    // 4. init_array（按顺序）
    LOGI("Calling %zu init_array functions", si->init_array_count);
    for (size_t i = 0; i < si->init_array_count; ++i) {
        ElfW(Addr) func = si->init_array[i];
        if (func != 0) {
            LOGD("Calling init_array[%zu] at %p ...", i, (void*)func);
            CallCtor(func);
        }
    }
    return true;
}

} // namespace mylinker
