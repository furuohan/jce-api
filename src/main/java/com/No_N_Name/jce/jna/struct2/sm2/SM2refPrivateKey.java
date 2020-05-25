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

public class SM2refPrivateKey extends Structure implements IKeyPair{
    public int bits;
    public byte[] D = new byte[32];

    public SM2refPrivateKey() {
    }

    public SM2refPrivateKey(byte[] D) {
        this.bits = 256;
        this.D = D;
    }

    public int getBits() {
        return this.bits;
    }

    public byte[] getD() {
        return this.D;
    }

    public void decode(byte[] privateKey) throws CryptoException {
        this.bits = BytesUtil.bytes2int(privateKey);
        int pos = 4;
        System.arraycopy(privateKey, pos, this.D, 0, 32);
        pos = pos + this.D.length;
        if (pos != privateKey.length) {
            throw new CryptoException("inputData length != SM2PrivateKey length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(this.D);
        } catch (IOException var3) {
            throw new CryptoException("SM2refPrivateKey encode error.", var3);
        }

        return buf.toByteArray();
    }

    public int size() {
        return 36;
    }

    public static int sizeof() {
        return 36;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("   D: ").append((new BigInteger(1, this.D)).toString(16)).append(nl);
        return buf.toString();
    }

    protected List getFieldOrder() {
        return Arrays.asList("bits", "D");
    }

    public static class ByValue extends SM2refPrivateKey implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends SM2refPrivateKey implements Structure.ByReference {
        public ByReference() {
        }
    }
}
