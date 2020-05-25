package com.No_N_Name.jce.jna.struct2.ecdsa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import com.No_N_Name.jce.jna.api.CryptoException;
import com.No_N_Name.jce.jna.struct2.IKeyPair;
import com.sun.jna.Structure;

import com.No_N_Name.jce.provider.utils.BytesUtil;

public class ECDSArefPublicKey extends Structure implements IKeyPair{
    public int bits;
    public int curvetype;
    public byte[] x = new byte[80];
    public byte[] y = new byte[80];

    public int getBits() {
        return this.bits;
    }

    public int getCurvetype() {
        return this.curvetype;
    }

    public void setCurvetype(int curvetype) {
        this.curvetype = curvetype;
    }

    public byte[] getX() {
        return this.x;
    }

    public byte[] getY() {
        return this.y;
    }

    public ECDSArefPublicKey() {
    }

    public ECDSArefPublicKey(int bits, int curvetype, byte[] x, byte[] y) {
        this.bits = bits;
        this.curvetype = curvetype;
        if (x.length > 80) {
            System.arraycopy(x, x.length - 80, this.x, 0, this.x.length);
        } else {
            System.arraycopy(x, 0, this.x, this.x.length - x.length, x.length);
        }

        if (y.length > 80) {
            System.arraycopy(y, y.length - 80, this.y, 0, this.y.length);
        } else {
            System.arraycopy(y, 0, this.y, this.y.length - y.length, y.length);
        }

    }

    public int size() {
        return 168;
    }

    public static int sizeof() {
        return 168;
    }

    public void decode(byte[] publicKey) throws CryptoException {
        this.bits = BytesUtil.bytes2int(publicKey);
        int pos = 4;
        byte[] tmpBuffer = new byte[4];
        System.arraycopy(publicKey, pos, tmpBuffer, 0, tmpBuffer.length);
        this.curvetype = BytesUtil.bytes2int(tmpBuffer);
        pos = pos + tmpBuffer.length;
        System.arraycopy(publicKey, pos, this.x, 0, 80);
        pos += this.x.length;
        System.arraycopy(publicKey, pos, this.y, 0, 80);
        pos += this.y.length;
        if (pos != publicKey.length) {
            throw new CryptoException("inputData length != ECDSArefPublicKey length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(BytesUtil.int2bytes(this.curvetype));
            buf.write(this.x);
            buf.write(this.y);
        } catch (IOException var3) {
            throw new CryptoException("ECDSArefPublicKey encode error.", var3);
        }

        return buf.toByteArray();
    }

    public String toString() {
        return "ECDSArefPublicKey{bits=" + this.bits + ", curvetype=" + Integer.toHexString(this.curvetype) + ", X=" + BytesUtil.bytes2hex(this.x) + ", Y=" + BytesUtil.bytes2hex(this.y) + '}';
    }

    protected List getFieldOrder() {
        return Arrays.asList("bits", "curvetype", "x", "y");
    }

    public static class ByValue extends ECDSArefPublicKey implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends ECDSArefPublicKey implements Structure.ByReference {
        public ByReference() {
        }
    }
}
