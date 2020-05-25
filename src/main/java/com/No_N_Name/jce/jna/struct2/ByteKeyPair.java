package com.No_N_Name.jce.jna.struct2;

import com.No_N_Name.jce.provider.utils.BytesUtil;

public class ByteKeyPair {
    private byte[] pubKeyData;
    private byte[] priKeyData;

    public byte[] getPubKeyData() {
        return this.pubKeyData;
    }

    public byte[] getPriKeyData() {
        return this.priKeyData;
    }

    public ByteKeyPair(byte[] pubKeyData, byte[] priKeyData) {
        this.pubKeyData = pubKeyData;
        this.priKeyData = priKeyData;
    }

    public String toString() {
        return "ByteKeyPair\nPubKey=" + BytesUtil.bytes2hex(this.pubKeyData) + "\nPriKey=" + BytesUtil.bytes2hex(this.priKeyData);
    }
}
