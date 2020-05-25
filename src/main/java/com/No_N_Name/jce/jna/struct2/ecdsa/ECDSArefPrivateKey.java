package com.No_N_Name.jce.jna.struct2.ecdsa;

import com.No_N_Name.jce.jna.api.CryptoException;
import com.No_N_Name.jce.jna.struct2.IKeyPair;
import com.sun.jna.Structure;

import com.No_N_Name.jce.provider.utils.BytesUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class ECDSArefPrivateKey extends Structure implements IKeyPair{
    public int bits;
    public int curvetype;
    public byte[] D = new byte[80];

    public ECDSArefPrivateKey() {
    }

    public ECDSArefPrivateKey(int bits, int curvetype, byte[] D) {
        this.bits = bits;
        this.curvetype = curvetype;
        if (D.length > 80) {
            System.arraycopy(D, D.length - 80, this.D, 0, this.D.length);
        } else {
            System.arraycopy(D, 0, this.D, this.D.length - D.length, D.length);
        }

    }

    public int getBits() {
        return this.bits;
    }

    public int getCurvetype() {
        return this.curvetype;
    }

    public void setCurvetype(int curvetype) {
        this.curvetype = curvetype;
    }

    public byte[] getD() {
        return this.D;
    }

    public void decode(byte[] privateKey) throws CryptoException {
        this.bits = BytesUtil.bytes2int(privateKey);
        int pos = 4;
        byte[] tmpBuffer = new byte[4];
        System.arraycopy(privateKey, pos, tmpBuffer, 0, tmpBuffer.length);
        this.curvetype = BytesUtil.bytes2int(tmpBuffer);
        pos = pos + tmpBuffer.length;
        System.arraycopy(privateKey, pos, this.D, 0, 80);
        pos += this.D.length;
        if (pos != privateKey.length) {
            throw new CryptoException("inputData length != ECDSAPrivateKey length");
        }
    }

    public byte[] encode() throws CryptoException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(BytesUtil.int2bytes(this.curvetype));
            buf.write(this.D);
        } catch (IOException var3) {
            throw new CryptoException("ECDSArefPrivateKey encode error.", var3);
        }

        return buf.toByteArray();
    }

    public int size() {
        return 88;
    }

    public String toString() {
        return "ECDSArefPrivateKey{bits=" + this.bits + ", curvetype=" + Integer.toHexString(this.curvetype) + ", D=" + BytesUtil.bytes2hex(this.D) + '}';
    }

    protected List getFieldOrder() {
        return Arrays.asList("bits", "curvetype", "D");
    }

    public static class ByValue extends ECDSArefPrivateKey implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends ECDSArefPrivateKey implements Structure.ByReference {
        public ByReference() {
        }
    }
	
	
}
