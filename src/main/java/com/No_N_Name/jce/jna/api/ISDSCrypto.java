package com.No_N_Name.jce.jna.api;

import com.No_N_Name.jce.jna.struct2.DeviceInfo;
import com.No_N_Name.jce.jna.struct2.DeviceRunStatus;
import com.No_N_Name.jce.jna.struct2.IDSArefPrivateKey;
import com.No_N_Name.jce.jna.struct2.IDSArefPublicKey;
import com.No_N_Name.jce.jna.struct2.IRSArefPrivateKey;
import com.No_N_Name.jce.jna.struct2.IRSArefPublicKey;
import com.No_N_Name.jce.jna.struct2.dsa.DSArefKeyPair;
import com.No_N_Name.jce.jna.struct2.dsa.DSArefSignature;
import com.No_N_Name.jce.jna.struct2.ecdsa.ECDSArefKeyPair;
import com.No_N_Name.jce.jna.struct2.ecdsa.ECDSArefPrivateKey;
import com.No_N_Name.jce.jna.struct2.ecdsa.ECDSArefPublicKey;
import com.No_N_Name.jce.jna.struct2.ecdsa.ECDSArefSignature;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefKeyPair;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refCipher;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refKeyPair;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refPrivateKey;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refPublicKey;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refSignature;

public interface ISDSCrypto {
	   DeviceInfo getDeviceInfo() throws CryptoException;

	   DeviceRunStatus getDeviceRunStatus() throws CryptoException;

	   int[] getKeyStatus(int var1) throws CryptoException;

	   byte[] generateRandom(int var1) throws CryptoException;

	   IRSArefPublicKey getRSAPublicKey(int var1, int var2) throws CryptoException;

	   RSArefKeyPair generateRSAKeyPair(int var1) throws CryptoException;

	   RSArefKeyPair generateRSAKeyPair(int var1, int var2) throws CryptoException;

	   void generateRSAKeyPair(int var1, int var2, int var3) throws CryptoException;

	   byte[] rsaPublicKeyOperation(int var1, int var2, byte[] var3) throws CryptoException;

	   byte[] rsaPrivateKeyOperation(int var1, int var2, byte[] var3) throws CryptoException;

	   byte[] rsaPublicKeyOperation(IRSArefPublicKey var1, byte[] var2) throws CryptoException;

	   byte[] rsaPrivateKeyOperation(IRSArefPrivateKey var1, byte[] var2) throws CryptoException;

	   void rsaImportKeyPair(int var1, int var2, IRSArefPublicKey var3, IRSArefPrivateKey var4) throws CryptoException;

	   SM2refPublicKey getSM2PublicKey(int var1, int var2) throws CryptoException;

	   SM2refKeyPair generateSM2KeyPair(int var1) throws CryptoException;

	   void generateSM2KeyPair(int var1, int var2, int var3) throws CryptoException;

	   SM2refCipher sm2Encrypt(int var1, int var2, byte[] var3) throws CryptoException;

	   byte[] sm2Decrypt(int var1, int var2, SM2refCipher var3) throws CryptoException;

	   SM2refCipher sm2Encrypt(SM2refPublicKey var1, byte[] var2) throws CryptoException;

	   byte[] sm2Decrypt(SM2refPrivateKey var1, SM2refCipher var2) throws CryptoException;

	   SM2refSignature sm2Sign(int var1, int var2, byte[] var3) throws CryptoException;

	   boolean sm2Verify(int var1, int var2, byte[] var3, SM2refSignature var4) throws CryptoException;

	   SM2refSignature sm2Sign(SM2refPrivateKey var1, byte[] var2) throws CryptoException;

	   boolean sm2Verify(SM2refPublicKey var1, byte[] var2, SM2refSignature var3) throws CryptoException;

	   byte[] keyAgreement_SM2(int var1, int var2, SM2refPublicKey var3, SM2refPrivateKey var4, SM2refPublicKey var5, SM2refPublicKey var6, int var7, byte[] var8, byte[] var9) throws Exception;

	   void sm2ImportKeyPair(int var1, int var2, SM2refPublicKey var3, SM2refPrivateKey var4) throws CryptoException;

	   ECDSArefKeyPair generateECDSAKeyPair(int var1, int var2) throws CryptoException;

	   ECDSArefPublicKey getECDSAPublicKey(int var1, int var2) throws CryptoException;

	   ECDSArefSignature ecdsaSign(int var1, int var2, byte[] var3) throws CryptoException;

	   ECDSArefSignature ecdsaSign(ECDSArefPrivateKey var1, byte[] var2) throws CryptoException;

	   boolean ecdsaVerify(int var1, int var2, byte[] var3, ECDSArefSignature var4) throws CryptoException;

	   boolean ecdsaVerify(ECDSArefPublicKey var1, byte[] var2, ECDSArefSignature var3) throws CryptoException;

	   DSArefKeyPair generateDSAKeyPair(int var1) throws CryptoException;

	   IDSArefPublicKey getDSAPublicKey(int var1, int var2) throws CryptoException;

	   DSArefSignature dsaSign(int var1, int var2, byte[] var3) throws CryptoException;

	   DSArefSignature dsaSign(IDSArefPrivateKey var1, byte[] var2) throws CryptoException;

	   boolean dsaVerify(int var1, int var2, byte[] var3, DSArefSignature var4) throws CryptoException;

	   boolean dsaVerify(IDSArefPublicKey var1, byte[] var2, DSArefSignature var3) throws CryptoException;

	   void generateKey(int var1, int var2) throws CryptoException;

	   byte[] encrypt(int var1, byte[] var2, byte[] var3, byte[] var4) throws CryptoException;

	   byte[] decrypt(int var1, byte[] var2, byte[] var3, byte[] var4) throws CryptoException;

	   byte[] encrypt(int var1, int var2, byte[] var3, byte[] var4) throws CryptoException;

	   byte[] decrypt(int var1, int var2, byte[] var3, byte[] var4) throws CryptoException;

	   byte[] encrypt_add(int var1, byte[] var2, byte[] var3, byte[] var4, byte[] var5) throws CryptoException;

	   byte[] decrypt_add(int var1, byte[] var2, byte[] var3, byte[] var4, byte[] var5) throws CryptoException;

	   byte[] encrypt_add(int var1, int var2, byte[] var3, byte[] var4, byte[] var5) throws CryptoException;

	   byte[] decrypt_add(int var1, int var2, byte[] var3, byte[] var4, byte[] var5) throws CryptoException;

	   void inputKEK(int var1, byte[] var2) throws CryptoException;

	   void importKeyPair_ECC(int var1, int var2, int var3, byte[] var4) throws CryptoException;

	   void importEncKeyPair_ECC(int var1, byte[] var2) throws CryptoException;

	   byte[] genKCV(int var1) throws CryptoException;

	   byte[] generateHMAC(int var1, int var2, byte[] var3) throws CryptoException;

	   byte[] generateHMAC(int var1, byte[] var2, byte[] var3) throws CryptoException;

	   byte[] genPBKDF2Key(int var1, int var2, int var3, char[] var4, byte[] var5) throws CryptoException;

	   byte[] ecdhAgreement(int var1, int var2, byte[] var3) throws CryptoException;

	   byte[] ecdhAgreement(byte[] var1, byte[] var2) throws CryptoException;

	   int hsmCreateFile(String var1, int var2) throws CryptoException;

	   byte[] hsmReadFile(String var1, int var2, int var3) throws CryptoException;

	   int hsmWriteFile(String var1, int var2, byte[] var3) throws CryptoException;

	   int hsmDeleteFile(String var1) throws CryptoException;
}
