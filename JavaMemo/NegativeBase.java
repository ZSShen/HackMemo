import java.util.*;


public class BaseNegative2{

    public static void main(String []args){

        System.out.println(BaseNegative2.convertToDecimal("110001"));
        System.out.println(BaseNegative2.convertToDecimal("11101"));

        System.out.println(BaseNegative2.convertToBinaryString(-15));
        System.out.println(BaseNegative2.convertToBinaryString(13));
    }

    private static int convertToDecimal(String str) {

        int num = 0;
        int base = -2;

        for (int i = str.length() - 1, j = 0 ; i >= 0 ; --i, ++j) {
            char ch = str.charAt(i);
            int temp = (int) Math.pow(base, j) * Integer.valueOf(ch - '0');
            num += temp;
        }

        return num;
    }

    private static String convertToBinaryString(int num) {

        StringBuilder bdr = new StringBuilder();

        while (num != 0) {
            int rem = num % -2;
            num = num / -2;

            if (rem < 0) {
                rem += 2;
                num += 1;
            }

            bdr.append(rem);
        }

        bdr.reverse();
        return bdr.toString();
    }
}