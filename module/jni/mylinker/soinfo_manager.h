#pragma once

#include "soinfo.h"

namespace mylinker {

// 解析 .dynamic 段：符号表、哈希、重定位、init/init_array、DT_NEEDED。
class SoinfoManager {
public:
    // 从 load_bias 处的 .dynamic 表填充 soinfo。
    // 必须与 soinfo 的 base 一致（elf_loader 中赋值）。
    static bool PrelinkImage(Soinfo* si);
};

} // namespace mylinker
