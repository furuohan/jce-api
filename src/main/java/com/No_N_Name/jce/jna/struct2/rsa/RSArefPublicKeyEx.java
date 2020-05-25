package com.No_N_Name.jce.jna.struct2.rsa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import com.No_N_Name.jce.jna.api.CryptoException;
import com.No_N_Name.jce.jna.struct2.IRSArefPublicKey;
import com.sun.jna.Structure;
import com.No_N_Name.jce.provider.RSA.JCERSAPublicKey;
import com.No_N_Name.jce.provider.utils.BytesUtil;

public class RSArefPublicKeyEx extends Structure implements IRSArefPublicKey {
    public int bits;
    public byte[] m = new byte[512];
    public byte[] e = new byte[512];

    public RSArefPublicKeyEx() {
    }


    public RSArefPublicKeyEx(int bits, byte[] m, byte[] e) {
        if (m.length > 513) {
            throw new RuntimeException("n length[ " + m.length + " ]");
        } else {
            this.bits = bits;
            System.arraycopy(m, 0, this.m, 512 - m.length, m.length);
            if (e.length > 513) {
                throw new RuntimeException("e length[ " + e.length + " ]");
            } else {
                if (e[0] == 0 && e.length % 256 == 1) {
                    System.arraycopy(e, 1, this.e, 512 - (e.length - 1), e.length - 1);
                } else {
                    System.arraycopy(e, 0, this.e, 512 - e.length, e.length);
                }

            }
        }
    }

    public int getBits() {
        return this.bits;
    }

    public byte[] getM() {
        return this.m;
    }

    public byte[] getE() {
        return this.e;
    }

    public void decode(byte[] bytes) throws CryptoException {
        this.bits = BytesUtil.bytes2int(bytes);
        int pos = 4;
        System.arraycopy(bytes, pos, this.m, 0, 512);
        pos = pos + this.m.length;
        System.arraycopy(bytes, pos, this.e, 0, 512);
        pos += 512;
        if (pos != bytes.length) {
            throw new CryptoException("inputData length != ExRSAPublicKey length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(this.m);
            buf.write(this.e);
        } catch (IOException var3) {
            throw new CryptoException("RSArefPublicKeyEx encode error.", var3);
        }

        return buf.toByteArray();
    }

    public int size() {
        return 1028;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("   n: ").append((new BigInteger(1, this.m)).toString(16)).append(nl);
        buf.append("   e: ").append((new BigInteger(1, this.e)).toString(16)).append(nl);
        return buf.toString();
    }

    protected List getFieldOrder() {
        return Arrays.asList("bits", "m", "e");
    }

    public static class ByValue extends RSArefPublicKeyEx implements Structure.ByValue {
    }

    public static class ByReference extends RSArefPublicKeyEx implements Structure.ByReference {
    }

}
