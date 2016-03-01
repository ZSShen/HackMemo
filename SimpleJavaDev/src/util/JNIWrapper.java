package util;

public class JNIWrapper 
{
    static {
        System.loadLibrary("Jni"); 
    }

    private native void atEntry();
}
