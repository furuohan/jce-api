package com.No_N_Name.jce.provider.utils;


public class ByteUtil {
    public ByteUtil() {
    }

    public static byte[] StringToByte(String str) {
        byte[] bytes = new byte[str.length() * 2];
        byte[] tmp = null;

        for(int i = 0; i < str.length(); ++i) {
            tmp = CharToByte(str.charAt(i));
            bytes[i * 2] = tmp[0];
            bytes[i * 2 + 1] = tmp[1];
        }

        return bytes;
    }

    public static String ByteToString(byte[] bytes) {
        String str = "";
        byte[] tmp = new byte[2];

        for(int i = 0; i < str.length(); ++i) {
            tmp[0] = bytes[i * 2];
            tmp[1] = bytes[i * 2 + 1];
            str = str + ByteToChar(tmp);
        }

        return str;
    }

    public static byte[] CharToByte(char num) {
        byte[] bytes = new byte[2];

        for(int i = 0; i < 2; ++i) {
            bytes[i] = (byte)(255 & num >> i * 8);
        }

        return bytes;
    }

    public static char ByteToChar(byte[] bytes) {
        char num = 0;

        for(int i = 0; i < 2; ++i) {
            num = (char)((int)((long)num + ((255L & (long)bytes[i]) << i * 8)));
        }

        return num;
    }

    public static byte[] ShortToByte(short num) {
        byte[] bytes = new byte[2];

        for(int i = 0; i < 2; ++i) {
            bytes[i] = (byte)(255 & num >> i * 8);
        }

        return bytes;
    }

    public static short ByteToShort(byte[] bytes) {
        short num = 0;

        for(int i = 0; i < 2; ++i) {
            num = (short)((int)((long)num + ((255L & (long)bytes[i]) << i * 8)));
        }

        return num;
    }

    public static byte[] int2bytes(int num) {
        byte[] bytes = new byte[4];

        for(int i = 0; i < 4; ++i) {
            bytes[3 - i] = (byte)(255 & num >> i * 8);
        }

        return bytes;
    }

    public static byte[] IntToByte(int num) {
        byte[] bytes = new byte[4];

        for(int i = 0; i < 4; ++i) {
            bytes[i] = (byte)(255 & num >> i * 8);
        }

        return bytes;
    }

    public static int ByteToInt(byte[] bytes) {
        int num = 0;

        for(int i = 0; i < 4; ++i) {
            num = (int)((long)num + ((255L & (long)bytes[i]) << i * 8));
        }

        return num;
    }

    public static byte[] LongToByte(long num) {
        byte[] bytes = new byte[8];

        for(int i = 0; i < 8; ++i) {
            bytes[i] = (byte)((int)(255L & num >> i * 8));
        }

        return bytes;
    }

    public static long ByteToLong(byte[] bytes) {
        long num = 0L;

        for(int i = 0; i < 8; ++i) {
            num += (255L & (long)bytes[i]) << i * 8;
        }

        return num;
    }

    public static byte[] FloatToByte(float num) {
        int n = Float.floatToIntBits(num);
        return IntToByte(n);
    }

    public static float ByteToFloat(byte[] b) {
        int n = ByteToInt(b);
        return Float.intBitsToFloat(n);
    }

    public static byte[] DoubleToByte(double num) {
        long n = Double.doubleToLongBits(num);
        return LongToByte(n);
    }

    public static double ByteToDouble(byte[] b) {
        long n = ByteToLong(b);
        return Double.longBitsToDouble(n);
    }
}
