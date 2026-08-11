#pragma once

#include "soinfo.h"

namespace mylinker {

// 重定位 + 调用构造函数。
class Relocator {
public:
    // LinkImage：执行全部重定位（PLT/GOT 与非 PLT），然后调用 init/init_array。
    // init/init_array 按 Android linker 约定以 (argc=0, argv=null, envp=environ) 调用。
    static bool LinkImage(Soinfo* si);
};

} // namespace mylinker
