package com.No_N_Name.jce.jna.struct2;

import com.No_N_Name.jce.jna.api.CryptoException;

public interface IKeyPair {
	    void decode(byte[] var1) throws CryptoException;

	    byte[] encode() throws CryptoException;

	    int size();
}
