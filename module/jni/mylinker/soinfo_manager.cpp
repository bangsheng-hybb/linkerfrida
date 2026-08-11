#include "soinfo_manager.h"

#include <elf.h>
#include <cstring>
#include <cstdio>

#include <android/log.h>

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "CustomLinker", __VA_ARGS__)

namespace mylinker {

bool SoinfoManager::PrelinkImage(Soinfo* si) {
    const ElfW(Dyn)* dyn = nullptr;
    size_t dyn_count = 0;

    // 从 base + p_vaddr 找到 PT_DYNAMIC 段
    for (size_t i = 0; i < si->phnum; ++i) {
        const ElfW(Phdr)* phdr = &si->phdr[i];
        if (phdr->p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn)*)(si->base + phdr->p_vaddr);
            dyn_count = phdr->p_memsz / sizeof(ElfW(Dyn));
            break;
        }
    }
    if (dyn == nullptr) {
        LOGE("PrelinkImage: no PT_DYNAMIC");
        return false;
    }
    si->dynamic = dyn;
    si->dynamic_count = dyn_count;

    // 第一遍：收集指针/计数类 tag（NEEDED 依赖 STRTAB，必须两遍）
    for (size_t i = 0; i < dyn_count; ++i) {
        const ElfW(Dyn)* d = &dyn[i];
        switch (d->d_tag) {
            case DT_NULL:
                i = dyn_count; // 结束
                break;
            case DT_STRTAB:
                si->strtab = (const char*)(si->base + d->d_un.d_ptr);
                si->dynstr = si->strtab;
                break;
            case DT_STRSZ:
                si->strtab_size = d->d_un.d_val;
                si->dynstr_size = si->strtab_size;
                break;
            case DT_SYMTAB:
                si->symtab = (const ElfW(Sym)*)(si->base + d->d_un.d_ptr);
                break;
            case DT_GNU_HASH:
                si->gnu_hash = (const uint32_t*)(si->base + d->d_un.d_ptr);
                break;
            case DT_HASH:
                si->elf_hash = (const uint32_t*)(si->base + d->d_un.d_ptr);
                break;
            case DT_JMPREL:
                si->plt_rela = (const ElfW(Rela)*)(si->base + d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                si->plt_rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
                break;
            case DT_RELA:
                si->rela = (const ElfW(Rela)*)(si->base + d->d_un.d_ptr);
                break;
            case DT_RELASZ:
                si->rela_count = d->d_un.d_val / sizeof(ElfW(Rela));
                break;
            case DT_INIT:
                si->init_func = si->base + d->d_un.d_ptr;
                break;
            case DT_INIT_ARRAY:
                si->init_array = (const ElfW(Addr)*)(si->base + d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                si->init_array_count = d->d_un.d_val / sizeof(ElfW(Addr));
                break;
            case DT_FINI_ARRAY:
                si->fini_array = (const ElfW(Addr)*)(si->base + d->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                si->fini_array_count = d->d_un.d_val / sizeof(ElfW(Addr));
                break;
            default:
                break;
        }
    }

    // 第二遍：收集需要字符串表的 tag（DT_NEEDED 可能出现在 STRTAB 之前）
    if (si->strtab != nullptr) {
        for (size_t i = 0; i < dyn_count; ++i) {
            const ElfW(Dyn)* d = &dyn[i];
            if (d->d_tag == DT_NULL) break;
            if (d->d_tag == DT_NEEDED && d->d_un.d_val < si->strtab_size) {
                si->needed_libs.emplace_back(si->strtab + d->d_un.d_val);
            }
        }
    }

    if (si->symtab == nullptr || si->strtab == nullptr) {
        LOGE("PrelinkImage: missing symtab/strtab");
        return false;
    }
    return true;
}

} // namespace mylinker
