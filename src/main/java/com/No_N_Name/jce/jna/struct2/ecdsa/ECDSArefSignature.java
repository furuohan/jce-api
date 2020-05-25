package com.No_N_Name.jce.jna.struct2.ecdsa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import com.No_N_Name.jce.jna.api.CryptoException;
import com.No_N_Name.jce.jna.struct2.IKeyPair;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refSignature;
import com.sun.jna.Structure;

import com.No_N_Name.jce.provider.utils.BytesUtil;

public class ECDSArefSignature extends Structure implements IKeyPair{
    public byte[] r = new byte[80];
    public byte[] s = new byte[80];

    public ECDSArefSignature() {
    }

    public ECDSArefSignature(byte[] r, byte[] s) {
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
            throw new CryptoException("inputData length != ECDSArefSignature length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(this.r);
            buf.write(this.s);
        } catch (IOException var3) {
            throw new CryptoException("ECDSArefSignature encode error.", var3);
        }

        return buf.toByteArray();
    }

    public int size() {
        return this.r.length + this.s.length;
    }

    public String toString() {
        return "ECDSArefSignature{r=" + BytesUtil.bytes2hex(this.r) + ", s=" + BytesUtil.bytes2hex(this.s) + '}';
    }

    protected List getFieldOrder() {
        return Arrays.asList("r", "s");
    }

    public static class ByValue extends SM2refSignature implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends SM2refSignature implements Structure.ByReference {
        public ByReference() {
        }
    }

	
}
