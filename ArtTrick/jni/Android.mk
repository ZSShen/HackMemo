LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES 		:=  ./libffi/include \
						    ./libffi/linux-x86

LOCAL_MODULE            := VA

LOCAL_SRC_FILES         := JNIInvokeWithVA.cc \
						   ./libffi/src/debug.c \
						   ./libffi/src/prep_cif.c \
						   ./libffi/src/types.c \
						   ./libffi/src/raw_api.c \
						   ./libffi/src/java_raw_api.c \
						   ./libffi/src/x86/ffi.c \
						   ./libffi/src/x86/sysv.S

LOCAL_CFLAGS            := -g -fexceptions -fPIC

include $(BUILD_EXECUTABLE)
