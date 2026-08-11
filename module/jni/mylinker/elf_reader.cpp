#include "elf_reader.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>

#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "CustomLinker", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "CustomLinker", __VA_ARGS__)

namespace mylinker {

bool ElfReader::Open(const char* path) {
    fd_ = open(path, O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) {
        snprintf(error_, sizeof(error_), "open %s failed: %s", path, strerror(errno));
        LOGE("%s", error_);
        return false;
    }

    struct stat st;
    if (fstat(fd_, &st) != 0) {
        snprintf(error_, sizeof(error_), "fstat failed: %s", strerror(errno));
        LOGE("%s", error_);
        Close();
        return false;
    }
    file_size_ = (size_t)st.st_size;
    if (file_size_ < sizeof(ElfW(Ehdr))) {
        snprintf(error_, sizeof(error_), "file too small");
        LOGE("%s", error_);
        Close();
        return false;
    }

    // 只读 mmap 解析 ELF 头
    void* map = mmap(nullptr, file_size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (map == MAP_FAILED) {
        snprintf(error_, sizeof(error_), "mmap failed: %s", strerror(errno));
        LOGE("%s", error_);
        Close();
        return false;
    }
    ehdr_ = (const ElfW(Ehdr)*)map;
    if (memcmp(ehdr_->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr_->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr_->e_machine != EM_AARCH64) {
        snprintf(error_, sizeof(error_), "not a valid arm64 ELF");
        LOGE("%s", error_);
        munmap(map, file_size_);
        Close();
        return false;
    }

    phdr_num_ = ehdr_->e_phnum;
    if (ehdr_->e_phoff + phdr_num_ * sizeof(ElfW(Phdr)) > file_size_) {
        snprintf(error_, sizeof(error_), "program header out of range");
        LOGE("%s", error_);
        munmap(map, file_size_);
        Close();
        return false;
    }
    phdr_ = (const ElfW(Phdr)*)((const char*)map + ehdr_->e_phoff);

    // 计算 load bias：首个 PT_LOAD 的 p_vaddr 对齐到页
    for (size_t i = 0; i < phdr_num_; ++i) {
        if (phdr_[i].p_type == PT_LOAD) {
            load_bias_ = phdr_[i].p_vaddr & ~(ElfW(Addr))4095;
            break;
        }
    }

    // 保留 mmap 直到 LoadSegments 完成，由 elf_loader 调用 Close()
    map_ = map;
    return true;
}

void ElfReader::Close() {
    if (map_ != nullptr) {
        munmap(map_, file_size_);
        map_ = nullptr;
    }
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    ehdr_ = nullptr;
    phdr_ = nullptr;
}

size_t ElfReader::GetReservedSize(const ElfW(Phdr)* phdr, size_t phnum) {
    ElfW(Addr) min_vaddr = (ElfW(Addr))-1;
    ElfW(Addr) max_vaddr = 0;
    for (size_t i = 0; i < phnum; ++i) {
        if (phdr[i].p_type != PT_LOAD) continue;
        ElfW(Addr) start = phdr[i].p_vaddr & ~(ElfW(Addr))4095;
        ElfW(Addr) end = (phdr[i].p_vaddr + phdr[i].p_memsz + 4095) & ~(ElfW(Addr))4095;
        if (start < min_vaddr) min_vaddr = start;
        if (end > max_vaddr) max_vaddr = end;
    }
    if (min_vaddr == (ElfW(Addr))-1) return 0;
    return max_vaddr - min_vaddr;
}

} // namespace mylinker
