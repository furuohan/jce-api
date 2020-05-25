package com.No_N_Name.jce.jna.api;

import java.math.BigInteger;
import java.util.logging.Logger;

import com.No_N_Name.jce.jna.SDFInterface;
import com.No_N_Name.jce.jna.struct2.DeviceInfo;
import com.No_N_Name.jce.jna.struct2.DeviceRunStatus;
import com.No_N_Name.jce.jna.struct2.GBErrorCode_SDR;
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
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPrivateKeyEx;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPrivateKeyLite;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPublicKeyEx;
import com.No_N_Name.jce.jna.struct2.rsa.RSArefPublicKeyLite;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refCipher;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refKeyPair;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refPrivateKey;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refPublicKey;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refSignature;
import com.No_N_Name.jce.log.CryptoLogger;
import com.No_N_Name.jce.provider.utils.ECDSAUtil;
import com.No_N_Name.jce.provider.utils.SymmetryUtil;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import com.No_N_Name.jce.provider.utils.BytesUtil;

public class LIBCrypto implements ISDSCrypto{
	   private static Logger logger;
	   private static PointerByReference phDeviceHandle;

		public LIBCrypto(String conf) throws CryptoException {
			set_config(conf);
			openDevice();
		}

		private int set_config(String conf) throws CryptoException {
			int flag = SDFInterface.instanseLib.sdf_set_config_file(conf);
			if (flag != 0) {
				logger.info(GBErrorCode_SDR.toErrorInfo(flag));
				throw new CryptoException("config error.....");
             }
			return flag;
		}
	   
	   private void openDevice() throws CryptoException {
	      if (phDeviceHandle == null) {
	         Class var1 = LIBCrypto.class;
	         synchronized(LIBCrypto.class) {
	            if (phDeviceHandle == null) {
	               PointerByReference ppDevice = new PointerByReference(Pointer.NULL);
	               int flag = SDFInterface.instanseLib.SDF_OpenDevice(ppDevice);
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	               }

	               phDeviceHandle = ppDevice;
	               logger.info("Device open.");
	            }
	         }
	      }

	   }

	   public DeviceInfo getDeviceInfo() throws CryptoException {
	      logger.info("-> LIBCrypto.getDeviceInfo()...");
	      DeviceInfo pstDeviceInfo = new DeviceInfo();
	      Pointer hDeviceHandle = phDeviceHandle.getValue();
	      PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	      boolean var11 = false;

	      int closeFlag;
	      try {
	         var11 = true;
	         closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         Pointer pSessionHandleHandle = ppSessionHandle.getValue();
	         int funFlag = SDFInterface.instanseLib.SDF_GetDeviceInfo(pSessionHandleHandle, pstDeviceInfo);
	         if (funFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(funFlag));
	            throw new CryptoException(GBErrorCode_SDR.toErrorInfo(funFlag));
	         }

	         var11 = false;
	      } catch (CryptoException var12) {
	         throw var12;
	      } finally {
	         if (var11) {
	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	         }
	      }

	      closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	      if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	         logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	      }

	      logger.info("-> LIBCrypto.getDeviceInfo() end.");
	      return pstDeviceInfo;
	   }

	   public DeviceRunStatus getDeviceRunStatus() throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public int[] getKeyStatus(int keyType) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] generateRandom(int randomLength) throws CryptoException {
	      logger.info("-> LIBCrypto.generateRandom()...");
	      logger.fine("randomLength:" + randomLength);
	      byte[] random = null;
	      if (randomLength <= 0) {
	         logger.info("Illegal Random Length.");
	         throw new CryptoException("Illegal Random Length.");
	      } else {
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var12 = false;
	         int closeFlag;
	         try {
	            var12 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }
	            random = new byte[randomLength];
	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            int flag = SDFInterface.instanseLib.SDF_GenerateRandom(pSessionHandle, randomLength, random);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var12 = false;
	         } catch (CryptoException var13) {
	            throw var13;
	         } finally {
	            if (var12) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         logger.fine("random:" + BytesUtil.bytes2hex(random));
	         logger.info("-> LIBCrypto.generateRandom() end.");
	         return random;
	      }
	   }

	   public IRSArefPublicKey getRSAPublicKey(int keyIndex, int keyType) throws CryptoException {
	      logger.info("-> LIBCrypto.getRSAPublicKey()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("keyType:" + keyType);
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else {
	         RSArefPublicKeyEx pRsaPubKey = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var13 = false;

	         int closeFlag;
	         try {
	            var13 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            pRsaPubKey = new RSArefPublicKeyEx();
	            int flag = 0;
	            if (keyType == 2) {
	            	flag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_RSA(pSessionHandle, keyIndex, pRsaPubKey);
	            } else {
	               flag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_RSA(pSessionHandle, keyIndex, pRsaPubKey);
	            }

	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var13 = false;
	         } catch (CryptoException var14) {
	            throw var14;
	         } finally {
	            if (var13) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         IRSArefPublicKey publicKey = null;
	         if (pRsaPubKey.bits <= 2048) {
	            publicKey = new RSArefPublicKeyLite(pRsaPubKey.getBits(), BytesUtil.subbytes(pRsaPubKey.getM(), 0, 256), BytesUtil.subbytes(pRsaPubKey.getM(), 256, 256));
	         } else {
	            publicKey = new RSArefPublicKeyEx(pRsaPubKey.getBits(), pRsaPubKey.getM(), pRsaPubKey.getE());
	         }

	         logger.fine("publicKey:" + publicKey.toString());
	         logger.info("-> LIBCrypto.getRSAPublicKey() end.");
	         return (IRSArefPublicKey)publicKey;
	      }
	   }

	   public RSArefKeyPair generateRSAKeyPair(int keysize) throws CryptoException {
	      logger.info("-> LIBCrypto.generateRSAKeyPair()...");
	      logger.fine("keysize" + keysize);
	      if (keysize >= 1024 && keysize <= 4096 && keysize % 128 == 0) {
	         IRSArefPublicKey pRsaPubKey = null;
	         IRSArefPrivateKey pRsaPriKey = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var13 = false;
	         int closeFlag;
	         try {
	            var13 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }
	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            if (keysize <= 2048) {
	               pRsaPubKey = new RSArefPublicKeyLite.ByReference();
	               pRsaPriKey = new RSArefPrivateKeyLite.ByReference();
	            } else {
	               pRsaPubKey = new RSArefPublicKeyEx.ByReference();
	               pRsaPriKey = new RSArefPrivateKeyEx.ByReference();
	            }
	            int flag = SDFInterface.instanseLib.SDF_GenerateKeyPair_RSA(pSessionHandle, keysize, (IRSArefPublicKey)pRsaPubKey, (IRSArefPrivateKey)pRsaPriKey);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }
	            var13 = false;
	         } catch (CryptoException var14) {
	            throw var14;
	         } finally {
	            if (var13) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }
	            }
	         }
	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }
	         logger.fine("pRsaPubKey:" + pRsaPubKey.toString());
	         logger.fine("pRsaPriKey:" + pRsaPriKey.toString());
	         logger.info("-> LIBCrypto.generateRSAKeyPair() end.");
	         return new RSArefKeyPair((IRSArefPublicKey)pRsaPubKey, (IRSArefPrivateKey)pRsaPriKey);
	      } else {
	         throw new CryptoException("Illegal key length:" + keysize + ".");
	      }
	   }

	   public RSArefKeyPair generateRSAKeyPair(int keysize, int exponent) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public void generateRSAKeyPair(int keyIndex, int keyType, int keysize) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] rsaPublicKeyOperation(int keyIndex, int keyType, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.rsaPublicKeyOperation()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("keyType:" + keyType);
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else if (input != null && 0 != input.length) {
	         byte[] pucDataOutput = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var21 = false;

	         int closeFlag;
	         try {
	            var21 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandleHandle = ppSessionHandle.getValue();
	            RSArefPublicKeyEx pRsaPubKey = new RSArefPublicKeyEx();
	            int keyFlag = 0;
	            if (keyType == 2) {
	               keyFlag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_RSA(pSessionHandleHandle, keyIndex, pRsaPubKey);
	            } else {
	               keyFlag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_RSA(pSessionHandleHandle, keyIndex, pRsaPubKey);
	            }

	            if (keyFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(keyFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(keyFlag));
	            }

	            IRSArefPublicKey publicKey = null;
	            if (pRsaPubKey.bits <= 2048) {
	               publicKey = new RSArefPublicKeyLite(pRsaPubKey.getBits(), BytesUtil.subbytes(pRsaPubKey.getM(), 0, 256), BytesUtil.subbytes(pRsaPubKey.getM(), 256, 256));
	            } else {
	               publicKey = new RSArefPublicKeyEx(pRsaPubKey.getBits(), pRsaPubKey.getM(), pRsaPubKey.getE());
	            }

	            int keyLenth = ((IRSArefPublicKey)publicKey).getBits() >> 3;
	            if (keyLenth != input.length) {
	               logger.info("Illegal input data length[" + keyLenth + "]:" + input.length);
	               throw new CryptoException("Illegal input data length[" + keyLenth + "]:" + input.length);
	            }

	            BigInteger inputInteger = new BigInteger(1, input);
	            BigInteger publicM = new BigInteger(1, ((IRSArefPublicKey)publicKey).getM());
	            if (inputInteger.compareTo(publicM) > 0) {
	               logger.info("Illegal input data >publickey.M");
	               throw new CryptoException("Illegal input data >publickey.M");
	            }

	            IntByReference puiOutputLength = new IntByReference(0);
	            pucDataOutput = new byte[input.length];
	            int flag = 0;
	            if (keyType == 1) {
	               flag = SDFInterface.instanseLib.SDF_InternalPublicKeyOperation_RSA(pSessionHandleHandle, keyIndex, 65792, input, input.length, pucDataOutput, puiOutputLength);
	            } else {
	               flag = SDFInterface.instanseLib.SDF_InternalPublicKeyOperation_RSA(pSessionHandleHandle, keyIndex, 66048, input, input.length, pucDataOutput, puiOutputLength);
	            }

	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var21 = false;
	         } catch (CryptoException var22) {
	            throw var22;
	         } finally {
	            if (var21) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	         logger.info("-> LIBCrypto.rsaPublicKeyOperation() end.");
	         return pucDataOutput;
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public byte[] rsaPrivateKeyOperation(int keyIndex, int keyType, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.rsaPrivateKeyOperation()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("keyType:" + keyType);
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else if (input != null && 0 != input.length) {
	         byte[] pucDataOutput = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var21 = false;

	         int closeFlag;
	         try {
	            var21 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandleHandle = ppSessionHandle.getValue();
	            RSArefPublicKeyEx pRsaPubKey = new RSArefPublicKeyEx();
	            int keyFlag = 0;
	            if (keyType == 2) {
	               keyFlag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_RSA(pSessionHandleHandle, keyIndex, pRsaPubKey);
	            } else {
	               keyFlag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_RSA(pSessionHandleHandle, keyIndex, pRsaPubKey);
	            }

	            if (keyFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(keyFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(keyFlag));
	            }

	            IRSArefPublicKey publicKey = null;
	            if (pRsaPubKey.bits <= 2048) {
	               publicKey = new RSArefPublicKeyLite(pRsaPubKey.getBits(), BytesUtil.subbytes(pRsaPubKey.getM(), 0, 256), BytesUtil.subbytes(pRsaPubKey.getM(), 256, 256));
	            } else {
	               publicKey = new RSArefPublicKeyEx(pRsaPubKey.getBits(), pRsaPubKey.getM(), pRsaPubKey.getE());
	            }

	            int keyLenth = ((IRSArefPublicKey)publicKey).getBits() >> 3;
	            if (keyLenth != input.length) {
	               logger.info("Illegal input data length[" + keyLenth + "]:" + input.length);
	               throw new CryptoException("Illegal input data length[" + keyLenth + "]:" + input.length);
	            }

	            BigInteger inputInteger = new BigInteger(1, input);
	            BigInteger publicM = new BigInteger(1, ((IRSArefPublicKey)publicKey).getM());
	            if (inputInteger.compareTo(publicM) > 0) {
	               logger.info("Illegal input data >publickey.M");
	               throw new CryptoException("Illegal input data >publickey.M");
	            }

	            IntByReference puiOutputLength = new IntByReference(0);
	            pucDataOutput = new byte[input.length];
	            int flag = 0;
	            if (keyType == 1) {
	               flag = SDFInterface.instanseLib.SDF_InternalPrivateKeyOperation_RSA(pSessionHandleHandle, keyIndex, 65792, input, input.length, pucDataOutput, puiOutputLength);
	            } else {
	               flag = SDFInterface.instanseLib.SDF_InternalPrivateKeyOperation_RSA(pSessionHandleHandle, keyIndex, 66048, input, input.length, pucDataOutput, puiOutputLength);
	            }

	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var21 = false;
	         } catch (CryptoException var22) {
	            throw var22;
	         } finally {
	            if (var21) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	         logger.info("-> LIBCrypto.rsaPrivateKeyOperation() end.");
	         return pucDataOutput;
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public byte[] rsaPublicKeyOperation(IRSArefPublicKey refPublicKey, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.rsaPublicKeyOperation()...");
	      logger.fine("refPublicKey:" + refPublicKey);
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (refPublicKey == null) {
	         logger.info("The PublicKey data is null.");
	         throw new CryptoException("The PublicKey data is null.");
	      } else if (input != null && 0 != input.length) {
	         if (refPublicKey.getBits() >> 3 != input.length) {
	        	 int a = refPublicKey.getBits()>>3;
	        	 System.out.println(refPublicKey.getBits()+" "+a);
	            logger.info("Illegal input data length:" + input.length);
	            throw new CryptoException("Illegal input data length:" + input.length);
	         } else {
	            BigInteger inputInteger = new BigInteger(1, input);
	            BigInteger publicM = new BigInteger(1, refPublicKey.getM());
	            if (inputInteger.compareTo(publicM) > 0) {
	               logger.info("Illegal input data >publickey.M");
	               throw new CryptoException("Illegal input data >publickey.M");
	            } else {
	               byte[] pucDataOutput = null;
	               Pointer hDeviceHandle = phDeviceHandle.getValue();
	               PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	               boolean var16 = false;
	               int closeFlag;
	               try {
	                  var16 = true;
	                  closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                     throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }
	                  Pointer pSessionHandleHandle = ppSessionHandle.getValue();
	                  IntByReference puiOutputLength = new IntByReference(0);
	                  pucDataOutput = new byte[input.length];
	                  int flag = SDFInterface.instanseLib.SDF_ExternalPublicKeyOperation_RSA(pSessionHandleHandle, refPublicKey, input, input.length, pucDataOutput, puiOutputLength);
	                  if (flag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                     throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	                  }
	                  var16 = false;
	               } catch (CryptoException var17) {
	                  throw var17;
	               } finally {
	                  if (var16) {
	                     closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                     if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                        logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                     }
	                  }
	               }
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }
	               logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	               logger.info("-> LIBCrypto.rsaPublicKeyOperation() end.");
	               return pucDataOutput;
	            }
	         }
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public byte[] rsaPrivateKeyOperation(IRSArefPrivateKey refPrivateKey, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.rsaPrivateKeyOperation()...");
	      logger.fine("refPrivateKey:" + refPrivateKey.toString());
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (null == refPrivateKey) {
	         logger.info("The PrivateKey data is null.");
	         throw new CryptoException("The PrivateKey data is null.");
	      } else if (input != null && 0 != input.length) {
	         if (refPrivateKey.getBits() >> 3 != input.length) {
	            logger.info("Illegal input data length:" + input.length);
	            throw new CryptoException("Illegal input data length:" + input.length);
	         } else {
	            BigInteger inputInteger = new BigInteger(1, input);
	            BigInteger publicM = new BigInteger(1, refPrivateKey.getM());
	            if (inputInteger.compareTo(publicM) > 0) {
	               logger.info("Illegal input data > publickey.M");
	               throw new CryptoException("Illegal input data > publickey.M");
	            } else {
	               byte[] pucDataOutput = null;
	               Pointer hDeviceHandle = phDeviceHandle.getValue();
	               PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	               boolean var16 = false;
	               int closeFlag;
	               try {
	                  var16 = true;
	                  closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                     throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }
	                  Pointer pSessionHandleHandle = ppSessionHandle.getValue();
	                  IntByReference puiOutputLength = new IntByReference(0);
	                  pucDataOutput = new byte[input.length];
	                  int flag = SDFInterface.instanseLib.SDF_ExternalPrivateKeyOperation_RSA(pSessionHandleHandle, refPrivateKey, input, input.length, pucDataOutput, puiOutputLength);
	                  if (flag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                     throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	                  }
	                  var16 = false;
	               } catch (CryptoException var17) {
	                  throw var17;
	               } finally {
	                  if (var16) {
	                     closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                     if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                        logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                     }

	                  }
	               }
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }
	               logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	               logger.info("-> LIBCrypto.rsaPrivateKeyOperation() end.");
	               return pucDataOutput;
	            }
	         }
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public void rsaImportKeyPair(int keyIndex, int keyType, IRSArefPublicKey refPublicKey, IRSArefPrivateKey refPrivateKey) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public SM2refPublicKey getSM2PublicKey(int keyIndex, int keyType) throws CryptoException {
	      logger.info("-> LIBCrypto.getSM2PublicKey()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("keyType:" + keyType);
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else {
	         SM2refPublicKey pucPublicKey = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var13 = false;

	         int closeFlag;
	         try {
	            var13 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandleHandle = ppSessionHandle.getValue();
	            pucPublicKey = new SM2refPublicKey();
	            int flag = 0;
	            if (keyType == 1) {
	               flag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_ECC(pSessionHandleHandle, keyIndex, pucPublicKey);
	            } else {
	               flag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_ECC(pSessionHandleHandle, keyIndex, pucPublicKey);
	            }

	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var13 = false;
	         } catch (CryptoException var14) {
	            throw var14;
	         } finally {
	            if (var13) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         SM2refPublicKey publicKey = new SM2refPublicKey(pucPublicKey.getX(), pucPublicKey.getY());
	         logger.fine("publicKey:" + publicKey.toString());
	         logger.info("-> LIBCrypto.getSM2PublicKey() end.");
	         return publicKey;
	      }
	   }

	   public SM2refKeyPair generateSM2KeyPair(int keysize) throws CryptoException {
	      logger.info("-> LIBCrypto.generateSM2KeyPair()...");
	      logger.fine("keysize:" + keysize);
	      if (keysize != 256) {
	         logger.info("Illegal SM2 key length:" + keysize + ".");
	         throw new CryptoException("Illegal SM2 key length:" + keysize + ".");
	      } else {
	         SM2refPublicKey pucPublicKey = null;
	         SM2refPrivateKey pucPrivateKey = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var13 = false;
	         int closeFlag;
	         try {
	            var13 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }
	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            pucPublicKey = new SM2refPublicKey();
	            pucPrivateKey = new SM2refPrivateKey();
	            int flag = SDFInterface.instanseLib.SDF_GenerateKeyPair_ECC(pSessionHandle, 131072, keysize, pucPublicKey, pucPrivateKey);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }
	            var13 = false;
	         } catch (CryptoException var14) {
	            throw var14;
	         } finally {
	            if (var13) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }
	            }
	         }
	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }
	         logger.fine("pucPublicKey:" + pucPublicKey.toString());
	         logger.fine("pucPrivateKey:" + pucPrivateKey.toString());
	         logger.info("-> LIBCrypto.generateSM2KeyPair() end.");
	         return new SM2refKeyPair(pucPublicKey, pucPrivateKey);
	      }
	   }

	   public void generateSM2KeyPair(int keyIndex, int keyType, int keysize) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public SM2refCipher sm2Encrypt(int keyIndex, int keyType, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.sm2Encrypt()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else if (input != null && 0 != input.length) {
	         if (input.length > 136) {
	            logger.info("Illegal input data length:" + input.length + ".");
	            throw new CryptoException("Illegal input data length:" + input.length + ".");
	         } else {
	            SM2refCipher sm2refCipher = null;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var14 = false;

	            int closeFlag;
	            try {
	               var14 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               sm2refCipher = new SM2refCipher();
	               int flag = 0;
	               if (keyType == 1) {
	                  flag = SDFInterface.instanseLib.SDF_InternalEncrypt_ECC(pSessionHandle, keyIndex, 131328, input, input.length, sm2refCipher);
	               } else {
	                  flag = SDFInterface.instanseLib.SDF_InternalEncrypt_ECC(pSessionHandle, keyIndex, 132096, input, input.length, sm2refCipher);
	               }

	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	               }

	               var14 = false;
	            } catch (CryptoException var15) {
	               throw var15;
	            } finally {
	               if (var14) {
	                  closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }

	               }
	            }

	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            logger.fine("sm2refCipher:" + sm2refCipher.toString());
	            logger.info("-> LIBCrypto.sm2Encrypt() end.");
	            return sm2refCipher;
	         }
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public byte[] sm2Decrypt(int keyIndex, int keyType, SM2refCipher refCipher) throws CryptoException {
	      logger.info("-> LIBCrypto.sm2Decrypt()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("refCipher:" + refCipher.toString());
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else if (refCipher == null) {
	         logger.info("The SM2refCipher data is null.");
	         throw new CryptoException("The SM2refCipher data is null.");
	      } else {
	         byte[] pucDataOutput = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var15 = false;

	         int closeFlag;
	         try {
	            var15 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            IntByReference puiOutputLength = new IntByReference(0);
	            pucDataOutput = new byte[refCipher.cLength];
	            int flag = 0;
	            if (keyType == 1) {
	               flag = SDFInterface.instanseLib.SDF_InternalDecrypt_ECC(pSessionHandle, keyIndex, 131328, refCipher, pucDataOutput, puiOutputLength);
	            } else {
	               flag = SDFInterface.instanseLib.SDF_InternalDecrypt_ECC(pSessionHandle, keyIndex, 132096, refCipher, pucDataOutput, puiOutputLength);
	            }

	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var15 = false;
	         } catch (CryptoException var16) {
	            throw var16;
	         } finally {
	            if (var15) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	         logger.info("-> LIBCrypto.sm2Decrypt() end.");
	         return pucDataOutput;
	      }
	   }

	   public SM2refCipher sm2Encrypt(SM2refPublicKey publicKey, byte[] dataInput) throws CryptoException {
	      logger.info("-> LIBCrypto.sm2Encrypt()...");
	      logger.fine("publicKey:" + publicKey.toString());
	      logger.fine("dataInput:" + BytesUtil.bytes2hex(dataInput));
	      if (publicKey == null) {
	         logger.info("The SM2refPublicKey data is null.");
	         throw new CryptoException("The SM2refPublicKey data is null.");
	      } else if (dataInput != null && 0 != dataInput.length) {
	         if (dataInput.length > 136) {
	            logger.info("Illegal input data length:" + dataInput.length + ".");
	            throw new CryptoException("Illegal input data length:" + dataInput.length + ".");
	         } else {
	            SM2refCipher sm2refCipher = null;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var13 = false;

	            int closeFlag;
	            try {
	               var13 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               sm2refCipher = new SM2refCipher();
	               int flag = SDFInterface.instanseLib.SDF_ExternalEncrypt_ECC(pSessionHandle, 132096, publicKey, dataInput, dataInput.length, sm2refCipher);
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	               }

	               var13 = false;
	            } catch (CryptoException var14) {
	               throw var14;
	            } finally {
	               if (var13) {
	                  closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }
	               }
	            }
	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }
	            logger.fine("sm2refCipher:" + sm2refCipher.toString());
	            logger.info("-> LIBCrypto.sm2Encrypt() end.");
	            return sm2refCipher;
	         }
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public byte[] sm2Decrypt(SM2refPrivateKey privateKey, SM2refCipher refCipher) throws CryptoException {
	      logger.info("-> LIBCrypto.sm2Decrypt()...");
	      logger.fine("privateKey:" + privateKey.toString());
	      logger.fine("refCipher:" + refCipher.toString());
	      if (privateKey == null) {
	         logger.info("The SM2refPrivateKey data is null.");
	         throw new CryptoException("The SM2refPrivateKey data is null.");
	      } else if (refCipher == null) {
	         logger.info("The SM2refCipher data is null.");
	         throw new CryptoException("The SM2refCipher data is null.");
	      } else {
	         byte[] pucDataOutput = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var14 = false;
	         int closeFlag;
	         try {
	            var14 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }
	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            IntByReference puiOutputLength = new IntByReference(0);
	            pucDataOutput = new byte[refCipher.cLength];
	            int flag = SDFInterface.instanseLib.SDF_ExternalDecrypt_ECC(pSessionHandle, 132096, privateKey, refCipher, pucDataOutput, puiOutputLength);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var14 = false;
	         } catch (CryptoException var15) {
	            throw var15;
	         } finally {
	            if (var14) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	         logger.info("-> LIBCrypto.sm2Decrypt() end.");
	         return pucDataOutput;
	      }
	   }

	   public SM2refSignature sm2Sign(int keyIndex, int keyType, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.sm2Sign()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else if (input != null && 0 != input.length) {
	         if (input.length != 32) {
	            logger.info("Illegal input data length:" + input.length + ".");
	            throw new CryptoException("Illegal input data length:" + input.length + ".");
	         } else {
	            SM2refSignature sm2refSignature = null;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var14 = false;

	            int closeFlag;
	            try {
	               var14 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               sm2refSignature = new SM2refSignature();
	               int flag = 0;
	               if (keyType == 1) {
	                  flag = SDFInterface.instanseLib.SDF_InternalSign_ECC_Ex(pSessionHandle, keyIndex, 131328, input, input.length, sm2refSignature);
	               } else {
	                  flag = SDFInterface.instanseLib.SDF_InternalSign_ECC_Ex(pSessionHandle, keyIndex, 132096, input, input.length, sm2refSignature);
	               }

	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	               }

	               var14 = false;
	            } catch (CryptoException var15) {
	               throw var15;
	            } finally {
	               if (var14) {
	                  closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }

	               }
	            }

	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            logger.fine("sm2refSignature:" + sm2refSignature.toString());
	            logger.info("-> LIBCrypto.sm2Sign() end.");
	            return sm2refSignature;
	         }
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public boolean sm2Verify(int keyIndex, int keyType, byte[] dataInput, SM2refSignature refSig) throws CryptoException {
	      logger.info("-> LIBCrypto.sm2Verify()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("dataInput:" + BytesUtil.bytes2hex(dataInput));
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else if (dataInput != null && 0 != dataInput.length) {
	         if (dataInput.length != 32) {
	            logger.info("Illegal input data length:" + dataInput.length + ".");
	            throw new CryptoException("Illegal input data length:" + dataInput.length + ".");
	         } else if (refSig == null) {
	            logger.info("The SM2refSignature data is null.");
	            throw new CryptoException("The SM2refSignature data is null.");
	         } else {
	            int flag = 1;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var14 = false;
	            int closeFlag;
	            try {
	               var14 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }
	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               if (keyType == 1) {
	                  flag = SDFInterface.instanseLib.SDF_InternalVerify_ECC_Ex(pSessionHandle, keyIndex, 131328, dataInput, dataInput.length, refSig);
	               } else {
	                  flag = SDFInterface.instanseLib.SDF_InternalVerify_ECC_Ex(pSessionHandle, keyIndex, 132096, dataInput, dataInput.length, refSig);
	               }
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  var14 = false;
	               } else {
	                  var14 = false;
	               }
	            } catch (CryptoException var15) {
	               throw var15;
	            } finally {
	               if (var14) {
	                 closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }
	               }
	            }
	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }
	            logger.info("-> LIBCrypto.sm2Verify() end.");
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.fine("result:false");
	               return false;
	            } else {
	               logger.fine("result:true");
	               return true;
	            }
	         }
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public SM2refSignature sm2Sign(SM2refPrivateKey refPrivateKey, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.sm2Sign()...");
	      logger.fine("refPrivateKey:" + refPrivateKey.toString());
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (refPrivateKey == null) {
	         logger.info("The SM2refPrivateKey data is null.");
	         throw new CryptoException("The SM2refPrivateKey data is null.");
	      } else if (input != null && 0 != input.length) {
	         if (input.length != 32) {
	            logger.info("Illegal input data length:" + input.length + ".");
	            throw new CryptoException("Illegal input data length:" + input.length + ".");
	         } else {
	            SM2refSignature sm2refSignature = null;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var13 = false;

	            int closeFlag;
	            try {
	               var13 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               sm2refSignature = new SM2refSignature();
	               int flag = SDFInterface.instanseLib.SDF_ExternalSign_ECC(pSessionHandle, 131328, refPrivateKey, input, input.length, sm2refSignature);
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	               }

	               var13 = false;
	            } catch (CryptoException var14) {
	               throw var14;
	            } finally {
	               if (var13) {
	                  closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }

	               }
	            }

	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            logger.fine("sm2refSignature:" + sm2refSignature.toString());
	            logger.info("-> LIBCrypto.sm2Sign() end.");
	            return sm2refSignature;
	         }
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public boolean sm2Verify(SM2refPublicKey refPublicKey, byte[] dataInput, SM2refSignature refSig) throws CryptoException {
	      logger.info("-> LIBCrypto.sm2Verify()...");
	      logger.fine("refPublicKey:" + refPublicKey.toString());
	      logger.fine("dataInput:" + BytesUtil.bytes2hex(dataInput));
	      logger.fine("refSig:" + refSig.toString());
	      if (refPublicKey == null) {
	         logger.info("The SM2refPublicKey data is null.");
	         throw new CryptoException("The SM2refPublicKey data is null.");
	      } else if (dataInput != null && 0 != dataInput.length) {
	         if (dataInput.length != 32) {
	            logger.info("Illegal input data length:" + dataInput.length + ".");
	            throw new CryptoException("Illegal input data length:" + dataInput.length + ".");
	         } else if (refSig == null) {
	            logger.info("The SM2refSignature data is null.");
	            throw new CryptoException("The SM2refSignature data is null.");
	         } else {
	            int flag = 1;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var13 = false;

	            int closeFlag;
	            try {
	               var13 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               flag = SDFInterface.instanseLib.SDF_ExternalVerify_ECC(pSessionHandle, 131328, refPublicKey, dataInput, dataInput.length, refSig);
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  var13 = false;
	               } else {
	                  var13 = false;
	               }
	            } catch (CryptoException var14) {
	               throw var14;
	            } finally {
	               if (var13) {
	                  closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }

	               }
	            }

	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            logger.info("-> LIBCrypto.sm2Verify() end.");
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.fine("result:false");
	               return false;
	            } else {
	               logger.fine("result:true");
	               return true;
	            }
	         }
	      } else {
	         logger.info("The input data is null.");
	         throw new CryptoException("The input data is null.");
	      }
	   }

	   public byte[] keyAgreement_SM2(int flag, int keyIndex, SM2refPublicKey ownTmpPubKey, SM2refPrivateKey ownTmpPriKey, SM2refPublicKey opPubKey, SM2refPublicKey opTmpPubKey, int keyBits, byte[] ownId, byte[] opId) throws Exception {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public void sm2ImportKeyPair(int keyIndex, int keyType, SM2refPublicKey refPublicKey, SM2refPrivateKey refPrivateKey) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public ECDSArefKeyPair generateECDSAKeyPair(int keysize, int curetype) throws CryptoException {
	      logger.info("-> LIBCrypto.generateECDSAKeyPair()...");
	      logger.fine("keysize:" + keysize);
	      logger.fine("curetype:" + curetype);
	      if (!ECDSAUtil.checkCurveType(curetype)) {
	         throw new CryptoException("Illegal ECDSA curve parameters( " + curetype + " )");
	      } else if (!ECDSAUtil.checkKeyLength(curetype, keysize)) {
	         throw new CryptoException("Illegal ECDSA curve parameters( " + curetype + " )," + "key modulus( " + keysize + " )");
	      } else {
	         ECDSArefPublicKey pucPublicKey = null;
	         ECDSArefPrivateKey pucPrivateKey = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var14 = false;

	         int closeFlag;
	         try {
	            var14 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            pucPublicKey = new ECDSArefPublicKey();
	            pucPrivateKey = new ECDSArefPrivateKey();
	            if (curetype == 524289) {
	               curetype = 0;
	            }

	            int flag = SDFInterface.instanseLib.SDF_GenerateKeyPair_ECDSA(pSessionHandle, 524288, keysize, curetype, pucPublicKey, pucPrivateKey);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var14 = false;
	         } catch (CryptoException var15) {
	            throw var15;
	         } finally {
	            if (var14) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         if (pucPublicKey.getCurvetype() == 0) {
	            pucPublicKey.setCurvetype(524289);
	            pucPrivateKey.setCurvetype(524289);
	         }

	         logger.fine("pucPublicKey:" + pucPublicKey.toString());
	         logger.fine("pucPrivateKey:" + pucPrivateKey.toString());
	         logger.info("-> LIBCrypto.generateECDSAKeyPair() end.");
	         return new ECDSArefKeyPair(pucPublicKey, pucPrivateKey);
	      }
	   }

	   public ECDSArefPublicKey getECDSAPublicKey(int keyIndex, int keyType) throws CryptoException {
	      logger.info("-> LIBCrypto.getECDSAPublicKey()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("keyType:" + keyType);
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else {
	         ECDSArefPublicKey pucPublicKey = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var13 = false;

	         int closeFlag;
	         try {
	            var13 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandleHandle = ppSessionHandle.getValue();
	            pucPublicKey = new ECDSArefPublicKey();
	            int flag = 0;
	            if (keyType == 1) {
	               flag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_ECDSA(pSessionHandleHandle, keyIndex, pucPublicKey);
	            } else {
	               flag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_ECDSA(pSessionHandleHandle, keyIndex, pucPublicKey);
	            }

	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var13 = false;
	         } catch (CryptoException var14) {
	            throw var14;
	         } finally {
	            if (var13) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         if (pucPublicKey.getCurvetype() == 0) {
	            pucPublicKey.setCurvetype(524289);
	         }

	         logger.fine("publicKey:" + pucPublicKey.toString());
	         logger.info("-> LIBCrypto.getECDSAPublicKey() end.");
	         return pucPublicKey;
	      }
	   }

	   public ECDSArefSignature ecdsaSign(int keyIndex, int keyType, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.ecdsaSign()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("keyType:" + keyType);
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else if (keyIndex < 1) {
	         throw new CryptoException("Illegal key index( " + keyIndex + " )");
	      } else if (input != null && input.length >= 1) {
	         ECDSArefSignature refSignature = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var18 = false;

	         int closeFlag;
	         try {
	            var18 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            IntByReference uiSignatureDataLength = new IntByReference(0);
	            refSignature = new ECDSArefSignature();
	            int flag = 0;
	            byte[] signOut = new byte[160];
	            if (keyType == 1) {
	               flag = SDFInterface.instanseLib.SDF_InternalSign_ECDSA(pSessionHandle, keyIndex, 524544, input, input.length, signOut, uiSignatureDataLength);
	            } else {
	               flag = SDFInterface.instanseLib.SDF_InternalSign_ECDSA(pSessionHandle, keyIndex, 524800, input, input.length, signOut, uiSignatureDataLength);
	            }

	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            int signLen = uiSignatureDataLength.getValue();
	            byte[] signResult = new byte[signLen];
	            System.arraycopy(signOut, 0, signResult, 0, signLen);
	            refSignature.decode(signResult);
	            var18 = false;
	         } catch (CryptoException var19) {
	            throw var19;
	         } finally {
	            if (var18) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         logger.fine("ecdsaRefSignature:" + refSignature.toString());
	         logger.info("-> LIBCrypto.ecdsaSign() end.");
	         return refSignature;
	      } else {
	         throw new CryptoException("Input data is null");
	      }
	   }

	   public ECDSArefSignature ecdsaSign(ECDSArefPrivateKey refPrivateKey, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.ecdsaSign()...");
	      logger.fine("refPrivateKey:" + refPrivateKey.toString());
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (refPrivateKey == null) {
	         logger.info("The ECDSArefPrivateKey data is null.");
	         throw new CryptoException("The ECDSArefPrivateKey data is null.");
	      } else if (input != null && input.length >= 1) {
	         ECDSArefSignature refSignature = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var17 = false;

	         int closeFlag;
	         try {
	            var17 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            IntByReference uiSignatureDataLength = new IntByReference(0);
	            refSignature = new ECDSArefSignature();
	            if (refPrivateKey.getCurvetype() == 524289) {
	               refPrivateKey.setCurvetype(0);
	            }

	            byte[] signOut = new byte[160];
	            int flag = SDFInterface.instanseLib.SDF_ExternalSign_ECDSA(pSessionHandle, 524544, refPrivateKey, input, input.length, signOut, uiSignatureDataLength);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            int signLen = uiSignatureDataLength.getValue();
	            byte[] signResult = new byte[signLen];
	            System.arraycopy(signOut, 0, signResult, 0, signLen);
	            refSignature.decode(signResult);
	            var17 = false;
	         } catch (CryptoException var18) {
	            throw var18;
	         } finally {
	            if (var17) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         logger.fine("ecdsaRefSignature:" + refSignature.toString());
	         logger.info("-> LIBCrypto.sm2Sign() end.");
	         return refSignature;
	      } else {
	         throw new CryptoException("Input data is null");
	      }
	   }

	   public boolean ecdsaVerify(int keyIndex, int keyType, byte[] dataInput, ECDSArefSignature refSig) throws CryptoException {
	      logger.info("-> LIBCrypto.ecdsaVerify()...");
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("dataInput:" + BytesUtil.bytes2hex(dataInput));
	      if (keyIndex < 1) {
	         throw new CryptoException("Illegal key index( " + keyIndex + " )");
	      } else if (keyType != 1 && keyType != 2) {
	         logger.info("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	         throw new CryptoException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
	      } else if (dataInput != null && dataInput.length >= 1) {
	         if (refSig == null) {
	            logger.info("The ECDSArefSignature data is null.");
	            throw new CryptoException("The ECDSArefSignature data is null.");
	         } else {
	            int flag = 1;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var14 = false;

	            int closeFlag;
	            try {
	               var14 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               if (keyType == 1) {
	                  flag = SDFInterface.instanseLib.SDF_InternalVerify_ECDSA(pSessionHandle, keyIndex, 524544, dataInput, dataInput.length, refSig, refSig.size());
	               } else {
	                  flag = SDFInterface.instanseLib.SDF_InternalVerify_ECDSA(pSessionHandle, keyIndex, 524800, dataInput, dataInput.length, refSig, refSig.size());
	               }

	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  var14 = false;
	               } else {
	                  var14 = false;
	               }
	            } catch (CryptoException var15) {
	               throw var15;
	            } finally {
	               if (var14) {
	                  closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }

	               }
	            }

	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            logger.info("-> LIBCrypto.ecdsaVerify() end.");
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.fine("result:false");
	               return false;
	            } else {
	               logger.fine("result:true");
	               return true;
	            }
	         }
	      } else {
	         throw new CryptoException("Input data is null");
	      }
	   }

	   public boolean ecdsaVerify(ECDSArefPublicKey refPublicKey, byte[] dataInput, ECDSArefSignature refSig) throws CryptoException {
	      logger.info("-> LIBCrypto.ecdsaVerify()...");
	      logger.fine("refPublicKey:" + refPublicKey.toString());
	      logger.fine("dataInput:" + BytesUtil.bytes2hex(dataInput));
	      logger.fine("refSig:" + refSig.toString());
	      if (refPublicKey == null) {
	         logger.info("The ECDSArefPublicKey data is null.");
	         throw new CryptoException("The ECDSArefPublicKey data is null.");
	      } else if (dataInput != null && dataInput.length >= 1) {
	         if (refSig == null) {
	            logger.info("The ECDSArefSignature data is null.");
	            throw new CryptoException("The ECDSArefSignature data is null.");
	         } else {
	            int flag = 1;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var13 = false;

	            int closeFlag;
	            try {
	               var13 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	               if (refPublicKey.getCurvetype() == 524289) {
	                  refPublicKey.setCurvetype(0);
	               }

	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               flag = SDFInterface.instanseLib.SDF_ExternalVerify_ECDSA(pSessionHandle, 524544, refPublicKey, dataInput, dataInput.length, refSig, refSig.size());
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  var13 = false;
	               } else {
	                  var13 = false;
	               }
	            } catch (CryptoException var14) {
	               throw var14;
	            } finally {
	               if (var13) {
	                  closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }

	               }
	            }

	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            logger.info("-> LIBCrypto.ecdsaVerify() end.");
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.fine("result:false");
	               return false;
	            } else {
	               logger.fine("result:true");
	               return true;
	            }
	         }
	      } else {
	         throw new CryptoException("Input data is null");
	      }
	   }

	   public DSArefKeyPair generateDSAKeyPair(int keysize) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public IDSArefPublicKey getDSAPublicKey(int keyIndex, int keyType) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public DSArefSignature dsaSign(int keyIndex, int keyType, byte[] input) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public DSArefSignature dsaSign(IDSArefPrivateKey refPrivateKey, byte[] input) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public boolean dsaVerify(int keyIndex, int keyType, byte[] dataInput, DSArefSignature refSig) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public boolean dsaVerify(IDSArefPublicKey refPublicKey, byte[] dataInput, DSArefSignature refSig) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public void generateKey(int keyIndex, int keysize) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] encrypt(int algId, byte[] key, byte[] iv, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.encrypt()...");
	      logger.fine("algId:" + algId);
	      logger.fine("key:" + BytesUtil.bytes2hex(key));
	      logger.fine("iv:" + BytesUtil.bytes2hex(iv));
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (key != null && 0 != key.length) {
	         if (!SymmetryUtil.isRightAlg(algId)) {
	            logger.info("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
	            throw new CryptoException("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
	         } else if (!SymmetryUtil.isRightIV(algId, iv)) {
	            logger.info("IV data length error.");
	            throw new CryptoException("IV data length error.");
	         } else if (!SymmetryUtil.isRightInput(algId, input)) {
	            logger.info("Input data length error.");
	            throw new CryptoException("Input data length error.");
	         } else {
	            byte[] pucDataOutput = null;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var17 = false;

	            int closeFlag;
	            try {
	               var17 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               PointerByReference phKeyHandle = new PointerByReference(Pointer.NULL);
	               IntByReference puiOutputLength = new IntByReference(0);
	               int flag = SDFInterface.instanseLib.SDF_ImportKey(pSessionHandle, key, key.length, phKeyHandle);
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	               }

	               pucDataOutput = new byte[input.length];
	               flag = SDFInterface.instanseLib.SDF_Encrypt(pSessionHandle, phKeyHandle.getValue(), algId, iv, input, input.length, pucDataOutput, puiOutputLength);
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	               }

	               var17 = false;
	            } catch (CryptoException var18) {
	               throw var18;
	            } finally {
	               if (var17) {
	                  closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }

	               }
	            }

	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	            logger.info("-> LIBCrypto.encrypt() end.");
	            return pucDataOutput;
	         }
	      } else {
	         logger.info("The Key data is null.");
	         throw new CryptoException("The Key data is null.");
	      }
	   }

	   public byte[] decrypt(int algId, byte[] key, byte[] iv, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.decrypt()...");
	      logger.fine("algId:" + algId);
	      logger.fine("key:" + BytesUtil.bytes2hex(key));
	      logger.fine("iv:" + BytesUtil.bytes2hex(iv));
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (key != null && 0 != key.length) {
	         if (!SymmetryUtil.isRightAlg(algId)) {
	            logger.info("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
	            throw new CryptoException("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
	         } else if (!SymmetryUtil.isRightIV(algId, iv)) {
	            logger.info("IV data length error.");
	            throw new CryptoException("IV data length error.");
	         } else if (!SymmetryUtil.isRightInput(algId, input)) {
	            logger.info("Input data length error.");
	            throw new CryptoException("Input data length error.");
	         } else {
	            byte[] pucDataOutput = null;
	            Pointer hDeviceHandle = phDeviceHandle.getValue();
	            PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	            boolean var17 = false;

	            int closeFlag;
	            try {
	               var17 = true;
	               closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	               Pointer pSessionHandle = ppSessionHandle.getValue();
	               PointerByReference phKeyHandle = new PointerByReference(Pointer.NULL);
	               IntByReference puiOutputLength = new IntByReference(0);
	               int flag = SDFInterface.instanseLib.SDF_ImportKey(pSessionHandle, key, key.length, phKeyHandle);
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	               }

	               pucDataOutput = new byte[input.length];
	               flag = SDFInterface.instanseLib.SDF_Decrypt(pSessionHandle, phKeyHandle.getValue(), algId, iv, input, input.length, pucDataOutput, puiOutputLength);
	               if (flag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	                  throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	               }

	               var17 = false;
	            } catch (CryptoException var18) {
	               throw var18;
	            } finally {
	               if (var17) {
	                  closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	                  if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                     logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	                  }

	               }
	            }

	            closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	            logger.info("-> LIBCrypto.decrypt() end.");
	            return pucDataOutput;
	         }
	      } else {
	         logger.info("The Key data is null.");
	         throw new CryptoException("The Key data is null.");
	      }
	   }

	   public byte[] encrypt(int algId, int keyIndex, byte[] iv, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.encrypt()...");
	      logger.fine("algId:" + algId);
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("iv:" + BytesUtil.bytes2hex(iv));
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (!SymmetryUtil.isRightAlg(algId)) {
	         logger.info("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
	         throw new CryptoException("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
	      } else if (!SymmetryUtil.isRightIV(algId, iv)) {
	         logger.info("IV data length error.");
	         throw new CryptoException("IV data length error.");
	      } else if (!SymmetryUtil.isRightInput(algId, input)) {
	         logger.info("Input data length error.");
	         throw new CryptoException("Input data length error.");
	      } else {
	         byte[] pucDataOutput = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var17 = false;

	         int closeFlag;
	         try {
	            var17 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            PointerByReference phKeyHandle = new PointerByReference(Pointer.NULL);
	            IntByReference puiOutputLength = new IntByReference(0);
	            int flag = SDFInterface.instanseLib.SDF_GetSymmKeyHandle(pSessionHandle, keyIndex, phKeyHandle);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            pucDataOutput = new byte[input.length];
	            flag = SDFInterface.instanseLib.SDF_Encrypt(pSessionHandle, phKeyHandle.getValue(), algId, iv, input, input.length, pucDataOutput, puiOutputLength);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var17 = false;
	         } catch (CryptoException var18) {
	            throw var18;
	         } finally {
	            if (var17) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	         logger.info("-> LIBCrypto.encrypt() end.");
	         return pucDataOutput;
	      }
	   }

	   public byte[] decrypt(int algId, int keyIndex, byte[] iv, byte[] input) throws CryptoException {
	      logger.info("-> LIBCrypto.decrypt()...");
	      logger.fine("algId:" + algId);
	      logger.fine("keyIndex:" + keyIndex);
	      logger.fine("iv:" + BytesUtil.bytes2hex(iv));
	      logger.fine("input:" + BytesUtil.bytes2hex(input));
	      if (!SymmetryUtil.isRightAlg(algId)) {
	         logger.info("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
	         throw new CryptoException("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
	      } else if (!SymmetryUtil.isRightIV(algId, iv)) {
	         logger.info("IV data length error.");
	         throw new CryptoException("IV data length error.");
	      } else if (!SymmetryUtil.isRightInput(algId, input)) {
	         logger.info("Input data length error.");
	         throw new CryptoException("Input data length error.");
	      } else {
	         byte[] pucDataOutput = null;
	         Pointer hDeviceHandle = phDeviceHandle.getValue();
	         PointerByReference ppSessionHandle = new PointerByReference(Pointer.NULL);
	         boolean var17 = false;

	         int closeFlag;
	         try {
	            var17 = true;
	            closeFlag = SDFInterface.instanseLib.SDF_OpenSession(hDeviceHandle, ppSessionHandle);
	            if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(closeFlag));
	            }

	            Pointer pSessionHandle = ppSessionHandle.getValue();
	            PointerByReference phKeyHandle = new PointerByReference(Pointer.NULL);
	            IntByReference puiOutputLength = new IntByReference(0);
	            int flag = SDFInterface.instanseLib.SDF_GetSymmKeyHandle(pSessionHandle, keyIndex, phKeyHandle);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            pucDataOutput = new byte[input.length];
	            flag = SDFInterface.instanseLib.SDF_Decrypt(pSessionHandle, phKeyHandle.getValue(), algId, iv, input, input.length, pucDataOutput, puiOutputLength);
	            if (flag != GBErrorCode_SDR.SDR_OK) {
	               logger.info(GBErrorCode_SDR.toErrorInfo(flag));
	               throw new CryptoException(GBErrorCode_SDR.toErrorInfo(flag));
	            }

	            var17 = false;
	         } catch (CryptoException var18) {
	            throw var18;
	         } finally {
	            if (var17) {
	               closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	               if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	                  logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	               }

	            }
	         }

	         closeFlag = SDFInterface.instanseLib.SDF_CloseSession(ppSessionHandle.getValue());
	         if (closeFlag != GBErrorCode_SDR.SDR_OK) {
	            logger.info(GBErrorCode_SDR.toErrorInfo(closeFlag));
	         }

	         logger.fine("pucDataOutput:" + BytesUtil.bytes2hex(pucDataOutput));
	         logger.info("-> LIBCrypto.decrypt() end.");
	         return pucDataOutput;
	      }
	   }

	   public byte[] encrypt_add(int algId, byte[] key, byte[] iv, byte[] input, byte[] addInput) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] decrypt_add(int algId, byte[] key, byte[] iv, byte[] input, byte[] addInput) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] encrypt_add(int algId, int keyIndex, byte[] iv, byte[] input, byte[] addInput) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] decrypt_add(int algId, int keyIndex, byte[] iv, byte[] input, byte[] addInput) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public void inputKEK(int keyIndex, byte[] key) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public void importKeyPair_ECC(int keyIndex, int keyType, int keyPriKeyIndex, byte[] eccPairEnvelopedKey) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public void importEncKeyPair_ECC(int keyIndex, byte[] eccPairEnvelopedKey) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] genKCV(int keyIndex) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] generateHMAC(int algId, int keyIndex, byte[] input) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] generateHMAC(int algId, byte[] key, byte[] input) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] genPBKDF2Key(int hashAlg, int iteraCount, int outLength, char[] pwd, byte[] salt) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] ecdhAgreement(int ecdsIndex, int keyType, byte[] pubKey) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] ecdhAgreement(byte[] priKey, byte[] pubKey) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public int hsmCreateFile(String fileName, int maxLength) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public byte[] hsmReadFile(String fileName, int startPosition, int readLength) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public int hsmWriteFile(String fileName, int startPosition, byte[] data) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   public int hsmDeleteFile(String fileName) throws CryptoException {
	      throw new CryptoException("CardCrypto unrealized method...");
	   }

	   static {
	      logger = CryptoLogger.logger;
	      phDeviceHandle = null;
	   }

}
