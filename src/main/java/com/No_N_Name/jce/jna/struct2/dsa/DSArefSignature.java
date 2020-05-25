package com.No_N_Name.jce.jna.struct2.dsa;

import com.No_N_Name.jce.jna.api.CryptoException;
import com.No_N_Name.jce.jna.struct2.IKeyPair;
import com.sun.jna.Structure;

import com.No_N_Name.jce.provider.utils.BytesUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class DSArefSignature extends Structure implements IKeyPair{
    public byte[] r = new byte[32];
    public byte[] s = new byte[32];

    public DSArefSignature() {
    }

    public DSArefSignature(byte[] r, byte[] s) {
        this.r = r;
        this.s = s;
    }

    public byte[] getR() {
        return this.r;
    }

    public byte[] getS() {
        return this.s;
    }

    public void decode(byte[] signature) throws CryptoException {
        int pos = 0;
        int len = signature.length / 2;
        this.r = new byte[len];
        System.arraycopy(signature, pos, this.r, 0, len);
        pos = pos + len;
        this.s = new byte[len];
        System.arraycopy(signature, pos, this.s, 0, len);
        pos += len;
        if (pos != signature.length) {
            throw new CryptoException("inputData length != DSASignature length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(this.r);
            buf.write(this.s);
        } catch (IOException var3) {
            throw new CryptoException("DSArefSignature encode error.", var3);
        }

        return buf.toByteArray();
    }

    public int size() {
        return this.r.length + this.s.length;
    }

    public String toString() {
        return "DSArefSignature{r=" + BytesUtil.bytes2hex(this.r) + ", s=" + BytesUtil.bytes2hex(this.s) + '}';
    }

    protected List getFieldOrder() {
        return Arrays.asList("r", "s");
    }

    public static class ByValue extends DSArefSignature implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends DSArefSignature implements Structure.ByReference {
        public ByReference() {
        }
    }
}
