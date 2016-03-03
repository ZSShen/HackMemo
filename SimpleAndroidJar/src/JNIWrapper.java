
public class JNIWrapper 
{
    static {
        System.loadLibrary("Jni"); 
    }
    
    private native void atEntry(String arg_first, String arg_second);
    
    public void callAtEntry(String arg_first, String arg_second)
    {
        atEntry(arg_first, arg_second);
    }
}
