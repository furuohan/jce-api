package com.No_N_Name.jce.jna.struct2.dsa;

import com.No_N_Name.jce.jna.struct2.IDSArefPrivateKey;
import com.No_N_Name.jce.jna.struct2.IDSArefPublicKey;

public class DSArefKeyPair {
	 private IDSArefPrivateKey refPrivateKey;
	    private IDSArefPublicKey refPublicKey;

	    public DSArefKeyPair(IDSArefPublicKey publicKey, IDSArefPrivateKey privateKey) {
	        this.refPrivateKey = privateKey;
	        this.refPublicKey = publicKey;
	    }

	    public IDSArefPublicKey getPublicKey() {
	        return this.refPublicKey;
	    }

	    public IDSArefPrivateKey getPrivateKey() {
	        return this.refPrivateKey;
	    }

	    public String toString() {
	        return "DSArefKeyPair\nPublicKey:" + this.refPublicKey.toString() + "\n" + "PrivateKey:" + this.refPrivateKey.toString();
	    }
}
