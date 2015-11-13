LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE            := asm
LOCAL_SRC_FILES         := asm_site.S cpp_site.cc
LOCAL_CFLAGS            := -g -fexceptions

include $(BUILD_EXECUTABLE)
