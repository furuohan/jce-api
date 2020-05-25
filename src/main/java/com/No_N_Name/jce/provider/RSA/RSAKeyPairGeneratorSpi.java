package com.No_N_Name.jce.provider.RSA;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.util.logging.Logger;

import com.No_N_Name.jce.Info.Device_Info;
import com.No_N_Name.jce.jna.SDFInterface;
import com.No_N_Name.jce.jna.api.CryptoException;
import com.No_N_Name.jce.jna.api.LIBCrypto;
import com.No_N_Name.jce.jna.struct2.IRSArefPrivateKey;
import com.No_N_Name.jce.jna.struct2.IRSArefPublicKey;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefKeyPair;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPrivateKeyEx;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPrivateKeyLite;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPublicKeyEx;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPublicKeyLite;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;




public class RSAKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
	static final BigInteger defaultPublicExponent = BigInteger.valueOf(65537L);
	static final int defaultTests = 112;
	private SecureRandom random;
	private int keysize;

	@Override
	public void initialize(int keysize, SecureRandom random) {
		// TODO Auto-generated method stub
		System.out.println("KeyPairGenerator接受的Keysize： "+keysize);
		//random为随机数类
		this.random = random;
		this.keysize = keysize;
	}

	@Override
	public KeyPair generateKeyPair() {
		//返回两个钥匙对
			LIBCrypto libCrypto;
			JCERSAPublicKey publicKey = null;
			JCERSAPrivateKey privateKey= null;
			try {
				//额外：选择密码机算法
				libCrypto = new LIBCrypto("device_type=rpc\nrpc_host=166.111.134.50\nrpc_port=35555");
				RSArefKeyPair keyPair_var1 = libCrypto.generateRSAKeyPair(keysize);				
				publicKey = new JCERSAPublicKey(keyPair_var1.getPublicKey());
				privateKey = new JCERSAPrivateKey(keyPair_var1.getPrivateKey());
			} catch (CryptoException e) {
				e.printStackTrace();
			}
		return new KeyPair(publicKey, privateKey);
	}

}
