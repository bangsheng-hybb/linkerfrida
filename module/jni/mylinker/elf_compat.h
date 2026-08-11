#pragma once

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

// bionic 的 ElfW 宏在 link.h；这里统一为 arm64 64 位 ELF 提供等价定义，
// 避免 mylinker 头文件依赖具体 bionic 版本。
#ifndef ElfW
#define ElfW(type) Elf64_##type
#endif
