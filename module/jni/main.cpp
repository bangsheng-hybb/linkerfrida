#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits.h>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "zygisk.hpp"
#include "mylinker/elf_loader.h"

#define LOG_TAG "ZygiskGadget"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// KPM（KernelPatch Module）通信常量：supercall 45 的返回魔数
static constexpr uint32_t KPM_MAGIC = 0x4b504d48; // "KPMH"

extern "C" {
bool mylinker_load_library(const char* library_path, void* java_vm);
void* mylinker_get_symbol(const char* symbol_name);
void mylinker_cleanup();
}

// ---------- 极简扁平 JSON 解析（仅支持本模块配置格式） ----------
// config.json 格式（扁平，包名做顶层 key）：
// {
//   "com.xff.launch": {
//       "process": "com.xff.launch",
//       "inject": true,
//       "use_custom_linker": true,
//       "delay_us": 0,
//       "pin_module": true,
//       "gadget_name": "libhhh.so",
//       "gadget_config": "libhhh.config.so"
//   }
// }

namespace {

struct AppConfig {
    bool inject = false;
    bool use_custom_linker = false;
    bool pin_module = false; // 默认 false：模块加载完即被 DLCLOSE 卸载（进程无痕）
    int64_t delay_us = 0;
    std::string process;
    std::string gadget_name = "libhhh.so";
    std::string gadget_config = "libhhh.config.so";
};

// 从扁平 JSON 中取出某包名下的 { key: value, ... } 对象文本
std::string ExtractAppObject(const std::string& json, const std::string& pkg) {
    std::string key = "\"" + pkg + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return "";
    size_t brace = json.find('{', pos);
    if (brace == std::string::npos) return "";
    int depth = 0;
    for (size_t i = brace; i < json.size(); ++i) {
        if (json[i] == '{') depth++;
        else if (json[i] == '}') {
            depth--;
            if (depth == 0) return json.substr(brace, i - brace + 1);
        }
    }
    return "";
}

bool GetJsonBool(const std::string& obj, const std::string& key, bool def) {
    std::string k = "\"" + key + "\"";
    size_t pos = obj.find(k);
    if (pos == std::string::npos) return def;
    size_t colon = obj.find(':', pos);
    if (colon == std::string::npos) return def;
    size_t v = obj.find_first_of("tfn01", colon + 1);
    if (v == std::string::npos) return def;
    if (obj.compare(v, 4, "true") == 0) return true;
    if (obj.compare(v, 5, "false") == 0) return false;
    char* end = nullptr;
    long val = strtol(obj.c_str() + v, &end, 10);
    return val != 0;
}

std::string GetJsonString(const std::string& obj, const std::string& key, const std::string& def) {
    std::string k = "\"" + key + "\"";
    size_t pos = obj.find(k);
    if (pos == std::string::npos) return def;
    size_t colon = obj.find(':', pos);
    if (colon == std::string::npos) return def;
    size_t v = obj.find('"', colon + 1);
    if (v == std::string::npos) return def;
    size_t end = obj.find('"', v + 1);
    if (end == std::string::npos) return def;
    return obj.substr(v + 1, end - v - 1);
}

int64_t GetJsonInt(const std::string& obj, const std::string& key, int64_t def) {
    std::string k = "\"" + key + "\"";
    size_t pos = obj.find(k);
    if (pos == std::string::npos) return def;
    size_t colon = obj.find(':', pos);
    if (colon == std::string::npos) return def;
    char* end = nullptr;
    long long val = strtoll(obj.c_str() + colon + 1, &end, 10);
    if (end == obj.c_str() + colon + 1) return def;
    return val;
}

// 配置文件路径：优先 /data/adb/zygisk_gadget/config.json（持久化路径，不在 modules 下）
std::string ResolveConfigPath(const char* module_dir) {
    const char* primary = "/data/adb/zygisk_gadget/config.json";
    struct stat st;
    if (stat(primary, &st) == 0) return primary;
    std::string fallback = std::string(module_dir) + "/config.json";
    if (stat(fallback.c_str(), &st) == 0) return fallback;
    return primary; // 返回默认路径，由调用方兜底
}

std::string ReadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// KPM 在线探测：supercall 45（KernelPatch）。返回是否在线。
bool KpmPing() {
    long ret = syscall(45, 0, 0, 0, 0, 0, 0);
    return ret == KPM_MAGIC;
}

// fd → 路径（/proc/self/fd/N）
std::string FdToPath(int fd) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    char buf[PATH_MAX];
    ssize_t n = readlink(link, buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf);
}

} // namespace

// ---------- Zygisk 模块 ----------

class ZygiskGadget : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        if (args == nullptr) return;

        // getModuleDir 仅在 pre[XXX]Specialize 阶段可用（官方 API 约定）
        int fd = api_->getModuleDir();
        if (fd >= 0) {
            module_dir_ = FdToPath(fd);
            close(fd);
        }
        if (module_dir_.empty()) {
            LOGE("Failed to resolve module dir");
            return;
        }

        JNIEnv* env = env_;

        if (env != nullptr) {
            const char* name = env->GetStringUTFChars(args->nice_name, nullptr);
            if (name != nullptr) {
                app_name_ = name;
                env->ReleaseStringUTFChars(args->nice_name, name);
            }
            const char* dir = env->GetStringUTFChars(args->app_data_dir, nullptr);
            if (dir != nullptr) {
                app_data_dir_ = dir;
                env->ReleaseStringUTFChars(args->app_data_dir, dir);
            }
        }
        uid_ = args->uid;

        // 防止 zygote / 系统进程被误注入
        if (app_name_.empty() || app_name_ == "zygote" ||
            app_name_ == "system_server" || app_name_.find("android.") == 0) {
            return;
        }

        // 读取配置
        std::string cfg_path = ResolveConfigPath(module_dir_.c_str());
        std::string json = ReadFile(cfg_path);
        if (json.empty()) return;
        std::string obj = ExtractAppObject(json, app_name_);
        if (obj.empty()) return;

        config_.inject = GetJsonBool(obj, "inject", false);
        config_.use_custom_linker = GetJsonBool(obj, "use_custom_linker", false);
        config_.pin_module = GetJsonBool(obj, "pin_module", false);
        config_.delay_us = GetJsonInt(obj, "delay_us", 0);
        config_.gadget_name = GetJsonString(obj, "gadget_name", "libhhh.so");
        config_.gadget_config = GetJsonString(obj, "gadget_config", "libhhh.config.so");
        std::string proc = GetJsonString(obj, "process", "");
        config_.process = proc.empty() ? app_name_ : proc;

        // 关键：pre 阶段仍是 zygote 特权（SELinux 域未切换），
        // 此时读 /data/adb/modules 下的 gadget 与配置文件合法；
        // postAppSpecialize 后进程进入 app 沙箱，读 /data/adb 会被 avc deny。
        // 因此在 pre 阶段把文件内容全部读入内存，post 线程只写 app 私有目录。
        if (config_.inject) {
            gadget_buf_ = ReadFile(module_dir_ + "/libgadget.so");
            config_buf_ = ReadFile(module_dir_ + "/" + config_.gadget_config);
            if (gadget_buf_.empty()) {
                LOGE("Gadget file empty/missing: %s/libgadget.so", module_dir_.c_str());
                config_.inject = false;
            }
        }
    }

    void postAppSpecialize(const AppSpecializeArgs*) override {
        if (!config_.inject) return;

        LOGI("Frida-gadget injection thread start for %s, gadget name: %s, "
             "usleep: %lld, use_custom_linker: %d",
             app_name_.c_str(), config_.gadget_name.c_str(),
             (long long)config_.delay_us, config_.use_custom_linker ? 1 : 0);

        // Pin 模块：Zygisk Next 在 postAppSpecialize 返回后默认 dlclose 卸载模块 SO，
        // 注入线程（尤其 delay_us > 0 时）可能还在执行模块内代码。
        // 无延迟时线程在 dlclose 前快速完成，不 pin 实现模块彻底无痕（文档设计）；
        // 配置了延迟则必须 pin（dlopen 提升引用计数阻止卸载）。
        bool pin = config_.pin_module || config_.delay_us > 0;
        if (pin) {
            std::string own = module_dir_ + "/zygisk/arm64-v8a.so";
            void* h = dlopen(own.c_str(), RTLD_NOW | RTLD_NODELETE);
            if (h != nullptr) {
                LOGD("Module pinned (refcount bumped), dlclose will not unmap");
            }
        }

        // 注入在线程中执行，避免阻塞 app 启动
        std::thread([this]() { DoInjection(); }).detach();
    }

    void preServerSpecialize(ServerSpecializeArgs*) override {}
    void postServerSpecialize(const ServerSpecializeArgs*) override {}

private:
    Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
    std::string module_dir_;
    std::string app_name_;
    std::string app_data_dir_;
    int uid_ = -1;
    AppConfig config_;
    // pre 阶段（zygote 特权）读入的内容，post 线程只写 app 目录
    std::string gadget_buf_;
    std::string config_buf_;

    void DoInjection() {
        if (config_.delay_us > 0) {
            usleep((useconds_t)config_.delay_us);
        }

        std::string target_dir = app_data_dir_ + "/";
        std::string gadget_path = target_dir + config_.gadget_name;

        // 1. 把 pre 阶段读入的 gadget 写入 app 私有目录（system linker 无法加载，我们自定义加载）
        if (!WriteFile(gadget_path, gadget_buf_)) {
            LOGE("Failed to write gadget to %s", gadget_path.c_str());
            return;
        }
        LOGD("Wrote gadget to %s", gadget_path.c_str());

        // 2. KPM 在线探测（仅日志）
        bool kpm = KpmPing();
        LOGD("KPM: PING -> %s", kpm ? "0x4b504d48 (present)" : "absent");

        bool loaded = false;
        if (config_.use_custom_linker) {
            // 3. 通过环境变量传 gadget 配置内容：
            //    custom linker 加载的 gadget 没有 our_path，load_config 找不到
            //    旁边的 .config.so 文件，必须直接传内容（见技术文档问题五）
            if (!config_buf_.empty()) {
                setenv("FRIDA_GADGET_CONFIG", config_buf_.c_str(), 1);
            }

            // 4. 自定义 linker 加载（内部会设 FRIDA_GADGET_RANGE 并消费）
            loaded = mylinker_load_library(gadget_path.c_str(), nullptr);

            unsetenv("FRIDA_GADGET_CONFIG"); // 立即清除
        } else {
            LOGI("Normal dlopen path not implemented, use_custom_linker=0");
        }

        if (loaded) {
            LOGI("Frida-gadget loaded via custom linker");
        } else {
            LOGE("Frida-gadget load failed");
        }

        // 5. 删除拷贝的 gadget 文件（不留磁盘痕迹）
        unlink(gadget_path.c_str());
        LOGD("Deleted gadget file: %s", gadget_path.c_str());
    }

    static bool WriteFile(const std::string& path, const std::string& data) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            LOGE("open target failed: %s", path.c_str());
            return false;
        }
        out.write(data.data(), (std::streamsize)data.size());
        out.flush();
        if (out.fail()) {
            LOGE("write target failed: %s", path.c_str());
            return false;
        }
        chmod(path.c_str(), 0755);
        return true;
    }
};

// ---------- 模块工厂 ----------

REGISTER_ZYGISK_MODULE(ZygiskGadget)
