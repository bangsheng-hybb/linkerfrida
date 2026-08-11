#pragma once

#include "soinfo.h"

namespace mylinker {

// 解析 ELF 文件头/程序头/动态段，填充 Soinfo 结构。
class ElfReader {
public:
    // Open/Read：打开文件并解析。
    // 成功返回 true；失败可通过 Error() 取原因。
    bool Open(const char* path);
    void Close();

    const char* Error() const { return error_; }

    // 以下仅供 MemoryManager/Relocator 使用。
    int fd() const { return fd_; }
    const ElfW(Ehdr)* ehdr() const { return ehdr_; }
    const ElfW(Phdr)* phdr() const { return phdr_; }
    size_t phdr_num() const { return phdr_num_; }
    size_t file_size() const { return file_size_; }
    ElfW(Addr) load_bias() const { return load_bias_; }

    // 从 program header 计算保留区大小（含对齐）。
    static size_t GetReservedSize(const ElfW(Phdr)* phdr, size_t phnum);

private:
    int fd_ = -1;
    void* map_ = nullptr; // 只读解析映射，Close 时释放
    const ElfW(Ehdr)* ehdr_ = nullptr;
    const ElfW(Phdr)* phdr_ = nullptr;
    size_t phdr_num_ = 0;
    size_t file_size_ = 0;
    ElfW(Addr) load_bias_ = 0;
    char error_[256] = {0};
};

} // namespace mylinker
