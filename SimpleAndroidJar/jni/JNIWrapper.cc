#include <iostream>
#include "JNIWrapper.h"


JNIEXPORT void JNICALL Java_JNIWrapper_atEntry(JNIEnv* env, jobject thiz,
                                     jstring arg_first, jstring arg_second)
{
    jboolean is_copy = false;
    const char* c_str_first = env->GetStringUTFChars(arg_first, &is_copy);
    const char* c_str_second = env->GetStringUTFChars(arg_second, &is_copy);
    std::cout << c_str_first << ' ' << c_str_second << std::endl;
}