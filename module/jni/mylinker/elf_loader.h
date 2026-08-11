#pragma once

#include "soinfo.h"

namespace mylinker {

// 自定义 ELF 加载器：绕过系统 linker，直接把 SO 映射进内存、重定位、调构造函数。
class ElfLoader {
public:
    // 加载一个 so 文件并执行其 init/init_array。
    // library_path: 目标 so 绝对路径
    // java_vm:      JavaVM*（用于需要在 init 中拿 JNIEnv 的场景，可为 null）
    // 成功返回 true，失败返回 false。
    bool LoadLibrary(const char* library_path, void* java_vm = nullptr);

    // 加载后通过 soinfo 查符号。
    void* GetSymbol(const char* symbol_name);

    // 卸载：释放映射与 soinfo（模块自身不调用，仅供完整生命周期测试）。
    void Cleanup();

    Soinfo* GetSoinfo() { return loaded_si_; }

private:
    Soinfo* loaded_si_ = nullptr;
};

} // namespace mylinker
