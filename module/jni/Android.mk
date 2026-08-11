LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := xiaojia
LOCAL_CPPFLAGS := -std=c++17 -O2 -fvisibility=hidden -Wall -Wextra
LOCAL_LDFLAGS := -Wl,-z,now -Wl,--hash-style=gnu
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_SRC_FILES := \
    main.cpp \
    mylinker/elf_loader.cpp \
    mylinker/elf_reader.cpp \
    mylinker/memory_manager.cpp \
    mylinker/relocator.cpp \
    mylinker/soinfo_manager.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)
