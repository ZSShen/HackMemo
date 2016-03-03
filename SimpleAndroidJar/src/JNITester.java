
public class JNITester 
{
    public static void main(String[] args)
    {
        if (args.length != 2) {
            System.out.println("JNITester ARG_FIRST ARG_SECOND");
            return;
        }
        
        JNIWrapper wrapper = new JNIWrapper();
        wrapper.callAtEntry(args[1], args[2]);
    }
}
