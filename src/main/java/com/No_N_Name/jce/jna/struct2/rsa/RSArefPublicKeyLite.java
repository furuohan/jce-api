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

public class RSArefPublicKeyLite extends Structure implements IRSArefPublicKey{
    public int bits;
    public byte[] m = new byte[256];
    public byte[] e = new byte[256];

    public RSArefPublicKeyLite(int bits, byte[] m, byte[] e) {
        if (m.length > 257) {
            throw new RuntimeException("n length[ " + m.length + " ]");
        } else {
            this.bits = bits;
            System.arraycopy(m, 0, this.m, 256 - m.length, m.length);
            if (e.length > 257) {
                throw new RuntimeException("e length[ " + e.length + " ]");
            } else {
                System.arraycopy(e, 0, this.e, 256 - e.length, e.length);
            }
        }
    }

    public RSArefPublicKeyLite() {
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

    public void decode(byte[] publicKey) throws CryptoException {
        this.bits = BytesUtil.bytes2int(publicKey);
        int pos = 4;
        System.arraycopy(publicKey, pos, this.m, 0, 256);
        pos = pos + this.m.length;
        System.arraycopy(publicKey, pos, this.e, 0, 256);
        pos += this.e.length;
        if (pos != publicKey.length) {
            throw new CryptoException("inputData length != RSAPublicKey length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            out.write(BytesUtil.int2bytes(this.bits));
            out.write(this.m);
            out.write(this.e);
        } catch (IOException var3) {
            throw new CryptoException("RSArefPublicKeyLite encode error.", var3);
        }

        return out.toByteArray();
    }

    public int size() {
        return 516;
    }

    public static int sizeof() {
        return 516;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("   m: ").append((new BigInteger(1, this.m)).toString(16)).append(nl);
        buf.append("   e: ").append((new BigInteger(1, this.e)).toString(16)).append(nl);
        return buf.toString();
    }

	protected List getFieldOrder() {
        return Arrays.asList("bits", "m", "e");
    }

    public static class ByValue extends RSArefPublicKeyLite implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends RSArefPublicKeyLite implements Structure.ByReference {
        public ByReference() {
        }
    }
}
