LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE            := memdump

LOCAL_C_INCLUDES        +=  ./

LOCAL_SRC_FILES         :=  stringprintf.cc \
                            memdump.cc \

LOCAL_CFLAGS            := -g -fexceptions

LOCAL_CPP_EXTENSION     := .cxx .cpp .cc

include $(BUILD_EXECUTABLE)
