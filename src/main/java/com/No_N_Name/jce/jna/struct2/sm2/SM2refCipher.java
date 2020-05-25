package com.No_N_Name.jce.jna.struct2.sm2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import com.No_N_Name.jce.jna.api.CryptoException;
import com.No_N_Name.jce.jna.struct2.IKeyPair;
import com.sun.jna.Structure;

import com.No_N_Name.jce.provider.utils.BytesUtil;

public class SM2refCipher extends Structure implements IKeyPair{
    public int cLength;
    public byte[] x = new byte[32];
    public byte[] y = new byte[32];
    public byte[] C = new byte[136];
    public byte[] M = new byte[32];

    public SM2refCipher() {
    }

    public SM2refCipher(byte[] x, byte[] y, byte[] c, byte[] m) {
        this.cLength = c.length;
        this.x = x;
        this.y = y;
        this.M = m;
        System.arraycopy(c, 0, this.C, 0, c.length);
    }

    public byte[] getX() {
        return this.x;
    }

    public byte[] getY() {
        return this.y;
    }

    public byte[] getC() {
        return this.C;
    }

    public byte[] getM() {
        return this.M;
    }

    public int getCLength() {
        return this.cLength;
    }

    public void decode(byte[] cipher) throws CryptoException {
        this.cLength = BytesUtil.bytes2int(cipher);
        int pos = 4;
        System.arraycopy(cipher, pos, this.x, 0, 32);
        pos = pos + this.x.length;
        System.arraycopy(cipher, pos, this.y, 0, 32);
        pos += this.y.length;
        System.arraycopy(cipher, pos, this.C, 0, 136);
        pos += this.C.length;
        System.arraycopy(cipher, pos, this.M, 0, 32);
        pos += this.M.length;
        if (pos != cipher.length) {
            throw new CryptoException("inputData length != SM2Cipher length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.cLength));
            buf.write(this.x);
            buf.write(this.y);
            buf.write(this.C);
            buf.write(this.M);
        } catch (IOException var3) {
            throw new CryptoException("SM2refCipher encode error.", var3);
        }

        return buf.toByteArray();
    }

    public int size() {
        return 236;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("cLength: ").append(this.cLength).append(nl);
        buf.append("      x: ").append((new BigInteger(1, this.x)).toString(16)).append(nl);
        buf.append("      y: ").append((new BigInteger(1, this.y)).toString(16)).append(nl);
        buf.append("      C: ").append((new BigInteger(1, this.C)).toString(16)).append(nl);
        buf.append("      M: ").append((new BigInteger(1, this.M)).toString(16)).append(nl);
        return buf.toString();
    }

    protected List getFieldOrder() {
        return Arrays.asList("cLength", "x", "y", "C", "M");
    }

    public static class ByValue extends SM2refCipher implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends SM2refCipher implements Structure.ByReference {
        public ByReference() {
        }
    }
}
