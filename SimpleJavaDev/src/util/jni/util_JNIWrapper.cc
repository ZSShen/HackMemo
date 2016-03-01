#include "util_JNIWrapper.h"
#include <iostream>


using namespace std;

void JNICALL Java_util_JNIWrapper_atEntry
  (JNIEnv *env, jobject receiver, jstring arg_first, jstring arg_second)
{
    jboolean is_copy = false;
    const char* c_str_first = env->GetStringUTFChars(arg_first, &is_copy);
    const char* c_str_second = env->GetStringUTFChars(arg_second, &is_copy);
    cout << c_str_first << ' ' << c_str_second << endl;
}
