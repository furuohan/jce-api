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

public class SM2refPublicKey extends Structure implements IKeyPair{
    public int bits;
    public byte[] x = new byte[32];
    public byte[] y = new byte[32];

    public SM2refPublicKey() {
    }

    public SM2refPublicKey(byte[] x, byte[] y) {
        this.bits = 256;
        this.x = x;
        this.y = y;
    }

    public int getBits() {
        return this.bits;
    }

    public byte[] getX() {
        return this.x;
    }

    public byte[] getY() {
        return this.y;
    }

    public void decode(byte[] publicKey) throws CryptoException {
        this.bits = BytesUtil.bytes2int(publicKey);
        int pos = 4;
        System.arraycopy(publicKey, pos, this.x, 0, 32);
        pos = pos + this.x.length;
        System.arraycopy(publicKey, pos, this.y, 0, 32);
        pos += this.y.length;
        if (pos != publicKey.length) {
            throw new CryptoException("inputData length != SM2PublicKey length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(this.x);
            buf.write(this.y);
        } catch (IOException var3) {
            throw new CryptoException("SM2refPublicKey encode error.", var3);
        }

        return buf.toByteArray();
    }

    public int size() {
        return 68;
    }

    public static int sizeof() {
        return 68;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("   X: ").append((new BigInteger(1, this.x)).toString(16)).append(nl);
        buf.append("   Y: ").append((new BigInteger(1, this.y)).toString(16)).append(nl);
        return buf.toString();
    }

    protected List getFieldOrder() {
        return Arrays.asList("bits", "x", "y");
    }

    public static class ByValue extends SM2refPublicKey implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends SM2refPublicKey implements Structure.ByReference {
        public ByReference() {
        }
    }
}
