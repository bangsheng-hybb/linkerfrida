#pragma once

#include "elf_compat.h"

#include <link.h>
#include <string>
#include <vector>

namespace mylinker {

// Android bionic style soinfo, simplified for the custom loader.
struct Soinfo {
    // ELF 信息
    ElfW(Addr) base = 0;             // load bias（映射基址）
    ElfW(Addr) size = 0;             // 总映射大小（含对齐）
    const ElfW(Phdr)* phdr = nullptr;
    ElfW(Half) phnum = 0;
    const char* name = nullptr;

    // .dynamic 解析结果
    const ElfW(Dyn)* dynamic = nullptr;
    size_t dynamic_count = 0;

    // 符号表
    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t strtab_size = 0;
    const char* dynstr = nullptr;
    size_t dynstr_size = 0;

    // GNU hash / ELF hash
    const uint32_t* gnu_hash = nullptr;
    const uint32_t* elf_hash = nullptr;

    // 重定位
    const ElfW(Rela)* plt_rela = nullptr;
    size_t plt_rela_count = 0;
    const ElfW(Rela)* rela = nullptr;
    size_t rela_count = 0;

    // 构造函数
    ElfW(Addr) init_func = 0;
    const ElfW(Addr)* init_array = nullptr;
    size_t init_array_count = 0;
    const ElfW(Addr)* fini_array = nullptr;
    size_t fini_array_count = 0;

    // DT_NEEDED 依赖
    std::vector<std::string> needed_libs;
};

} // namespace mylinker
