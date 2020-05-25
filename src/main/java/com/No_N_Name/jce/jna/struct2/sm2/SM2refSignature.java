package com.No_N_Name.jce.jna.struct2.sm2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import com.No_N_Name.jce.jna.api.CryptoException;
import com.No_N_Name.jce.jna.struct2.IKeyPair;
import com.sun.jna.Structure;

public class SM2refSignature extends Structure implements IKeyPair{
    public byte[] r = new byte[32];
    public byte[] s = new byte[32];

    public SM2refSignature() {
    }

    public SM2refSignature(byte[] r, byte[] s) {
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
        System.arraycopy(signature, pos, this.r, 0, 32);
        pos = pos + 32;
        System.arraycopy(signature, pos, this.s, 0, 32);
        pos += 32;
        if (pos != signature.length) {
            throw new CryptoException("inputData length != SM2Signature length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(this.r);
            buf.write(this.s);
        } catch (IOException var3) {
            throw new CryptoException("SM2refSignature encode error.", var3);
        }

        return buf.toByteArray();
    }

    public int size() {
        return 64;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("   R: ").append((new BigInteger(1, this.r)).toString(16)).append(nl);
        buf.append("   S: ").append((new BigInteger(1, this.s)).toString(16)).append(nl);
        return buf.toString();
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
