package com.No_N_Name.jce.provider.RSA;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import com.No_N_Name.jce.jna.api.CryptoException;
import com.No_N_Name.jce.jna.api.LIBCrypto;
import com.No_N_Name.jce.jna.struct2.IRSArefPrivateKey;
import com.No_N_Name.jce.jna.struct2.IRSArefPublicKey;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPrivateKeyEx;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPrivateKeyLite;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPublicKeyEx;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPublicKeyLite;
import com.No_N_Name.jce.provider.utils.BigIntegerUitl;
import com.No_N_Name.jce.provider.utils.BigIntegers;
import com.No_N_Name.jce.provider.utils.BytesUtil;

public class RSACipherSpi extends CipherSpi{
	private int opmode;
	private SecureRandom random;
	private Key key;
	
	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		byte[] result = null;
		if(opmode == Cipher.ENCRYPT_MODE){
			//加密模式
			LIBCrypto libCrypto;
			Object publicKey;
			 byte[] n;
	         byte[] e;
			JCERSAPublicKey k = (JCERSAPublicKey)key;
	            publicKey = null;
	            n = BigIntegers.asUnsignedByteArray(k.getModulus());
	            e = k.getPublicExponent().toByteArray();
	            int bits = k.getModulus().bitLength();
	            if (bits > 2048) {
	               publicKey = new RSArefPublicKeyEx(bits, n, e);
	            } else {
	               publicKey = new RSArefPublicKeyLite(bits, n, e);
	            }
			try {
				libCrypto = new LIBCrypto("device_type=rpc\nrpc_host=166.111.134.50:35555\nrpc_port=5000");
				result = libCrypto.rsaPublicKeyOperation((IRSArefPublicKey)publicKey,input);
			} catch (CryptoException ec) {
				ec.printStackTrace();
			}
		}
		else if(opmode == Cipher.DECRYPT_MODE) {
			//解密模式
			LIBCrypto libCrypto;
			try {
				libCrypto = new LIBCrypto("device_type=rpc\nrpc_host=166.111.134.50:35555\nrpc_port=5000");
				JCERSAPrivateKey k = (JCERSAPrivateKey)key;
				Object privatekey;
		         byte[] n;
		         byte[] e;
		         privatekey = null;
		         n = BigIntegers.asUnsignedByteArray(k.getModulus());
		         e = k.getPublicExponent().toByteArray();
		         byte[] d = k.getPrivateExponent().toByteArray();
		         byte[] q1 = k.getPrimeP().toByteArray();
		         byte[] q2 = k.getPrimeQ().toByteArray();
		         byte[] p1 = k.getPrimeExponentP().toByteArray();
		         byte[] p2 = k.getPrimeExponentQ().toByteArray();
		         
		         byte[] coef = k.getCrtCoefficient().toByteArray();
		         
				if (k.getModulus().bitLength() > 2048) {
					privatekey = new RSArefPrivateKeyEx(n, e, d, p1, p2, q1, q2, coef);
		            } else {
		            	privatekey = new RSArefPrivateKeyLite(n, e, d, p1, p2, q1, q2, coef);
		            }
				result = libCrypto.rsaPrivateKeyOperation((IRSArefPrivateKey)privatekey,input);
			} catch (CryptoException e) {
				e.printStackTrace();
			}
		}
		else {
			//错误
		}
		return result;
	}

	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

		
		return 0;
	}

	@Override
	protected int engineGetBlockSize() {
		
		return 0;
	}

	@Override
	protected byte[] engineGetIV() {
		
		return null;
	}

	@Override
	protected int engineGetOutputSize(int inputLen) {

		return 0;
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {

		return null;
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
		this.key = key;
		this.opmode = opmode;
		
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {

		
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {

		
	}

	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {

		
	}

	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {

		
	}

	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {

		return null;
	}

	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException {

		return 0;
	}
	

}
