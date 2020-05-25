package com.No_N_Name.jce.jna.struct2.rsa;

import com.No_N_Name.jce.jna.struct2.IRSArefPrivateKey;
import com.No_N_Name.jce.jna.struct2.IRSArefPublicKey;

public class RSArefKeyPair {
	  private IRSArefPrivateKey refPrivateKey;
	    private IRSArefPublicKey refPublicKey;

	    public RSArefKeyPair(IRSArefPublicKey publicKey, IRSArefPrivateKey privateKey) {
	        this.refPrivateKey = privateKey;
	        this.refPublicKey = publicKey;
	    }

	    public IRSArefPublicKey getPublicKey() {
	        return this.refPublicKey;
	    }

	    public IRSArefPrivateKey getPrivateKey() {
	        return this.refPrivateKey;
	    }

	    public String toString() {
	        return "RSArefKeyPair\nPublicKey:" + this.refPublicKey.toString() + "\n" + "PrivateKey:" + this.refPrivateKey.toString();
	    }
}
