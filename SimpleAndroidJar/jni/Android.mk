
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := Jni
LOCAL_SRC_FILES := JNIWrapper.cc

include $(BUILD_SHARED_LIBRARY)
