package com.No_N_Name.jce.jna;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.No_N_Name.jce.jna.struct2.DeviceInfo;
import com.No_N_Name.jce.jna.struct2.IRSArefPrivateKey;
import com.No_N_Name.jce.jna.struct2.IRSArefPublicKey;
import com.No_N_Name.jce.jna.struct2.ecdsa.ECDSArefPrivateKey;
import com.No_N_Name.jce.jna.struct2.ecdsa.ECDSArefPublicKey;
import com.No_N_Name.jce.jna.struct2.ecdsa.ECDSArefSignature;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refCipher;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refPrivateKey;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refPublicKey;
import com.No_N_Name.jce.jna.struct2.sm2.SM2refSignature;

public interface SDFInterface extends Library{
	SDFInterface instanseLib = (SDFInterface)Native.load("libsdf_core", SDFInterface.class);
	
	int sdf_set_config_file(String device_conf);
	
	int SDF_OpenDevice(PointerByReference var1);

    int SDF_CloseDevice(Pointer var1);

    int SDF_OpenSession(Pointer var1, PointerByReference var2);

    int SDF_CloseSession(Pointer var1);

    int SDF_GetDeviceInfo(Pointer var1, DeviceInfo var2);

    int SDF_GenerateRandom(Pointer var1, int var2, byte[] var3);

    int SDF_GetPrivateKeyAccessRight();

    int SDF_ReleasePrivateKeyAccessRight(Pointer var1, int var2);

    int SDF_ExportSignPublicKey_RSA(Pointer var1, int var2, IRSArefPublicKey var3);

    int SDF_ExportEncPublicKey_RSA(Pointer var1, int var2, IRSArefPublicKey var3);

    int SDF_GenerateKeyPair_RSA(Pointer var1, int var2, IRSArefPublicKey var3, IRSArefPrivateKey var4);

    int SDF_GenerateKeyWithIPK_RSA(Pointer var1, int var2, int var3, byte[] var4, IntByReference var5, PointerByReference var6);

    int SDF_GenerateKeyWithEPK_RSA(Pointer var1, int var2, IRSArefPublicKey var3, byte[] var4, IntByReference var5, PointerByReference var6);

    int SDF_ImportKeyWithISK_RSA(Pointer var1, int var2, byte[] var3, int var4, PointerByReference var5);

    int SDF_ExchangeDigitEnvelopeBaseOnRSA(Pointer var1, int var2, IRSArefPublicKey var3, byte[] var4, int var5, byte[] var6, IntByReference var7);

    int SDF_ExportSignPublicKey_ECC(Pointer var1, int var2, SM2refPublicKey var3);

    int SDF_ExportEncPublicKey_ECC(Pointer var1, int var2, SM2refPublicKey var3);

    int SDF_GenerateKeyPair_ECC(Pointer var1, int var2, int var3, SM2refPublicKey var4, SM2refPrivateKey var5);

    int SDF_GenerateKeyWithIPK_ECC(Pointer var1, int var2, int var3, SM2refCipher var4, PointerByReference var5);

    int SDF_GenerateKeyWithEPK_ECC(Pointer var1, int var2, int var3, SM2refPublicKey var4, SM2refCipher var5, PointerByReference var6);

    int SDF_ImportKeyWithISK_ECC(Pointer var1, int var2, SM2refCipher var3, PointerByReference var4);

    int SDF_GenerateAgreementDataWithECC(Pointer var1, int var2, int var3, byte[] var4, int var5, SM2refPublicKey var6, SM2refPublicKey var7, PointerByReference var8);

    int SDF_GenerateKeyWithECC(Pointer var1, PointerByReference var2, int var3, SM2refPublicKey var4, SM2refPublicKey var5, Pointer var6, PointerByReference var7);

    int SDF_GenerateAgreementDataAndKeyWithECC(Pointer var1, int var2, int var3, byte[] var4, int var5, byte[] var6, int var7, SM2refPublicKey var8, SM2refPublicKey var9, SM2refPublicKey var10, SM2refPublicKey var11, PointerByReference var12);

    int SDF_ExchangeDigitEnvelopeBaseOnECC(Pointer var1, int var2, int var3, SM2refPublicKey var4, SM2refCipher var5, SM2refCipher var6);

    int SDF_GenerateKeyWithKEK(Pointer var1, int var2, int var3, int var4, byte[] var5, IntByReference var6, PointerByReference var7);

    int SDF_ImportKeyWithKEK(Pointer var1, int var2, int var3, byte[] var4, int var5, PointerByReference var6);

    int SDF_ImportKey(Pointer var1, byte[] var2, int var3, PointerByReference var4);

    int SDF_DestroyKey(Pointer var1, Pointer var2);

    int SDF_ExternalPublicKeyOperation_RSA(Pointer var1, IRSArefPublicKey var2, byte[] var3, int var4, byte[] var5, IntByReference var6);

    int SDF_ExternalPrivateKeyOperation_RSA(Pointer var1, IRSArefPrivateKey var2, byte[] var3, int var4, byte[] var5, IntByReference var6);

    int SDF_InternalPublicKeyOperation_RSA(Pointer var1, int var2, int var3, byte[] var4, int var5, byte[] var6, IntByReference var7);

    int SDF_InternalPrivateKeyOperation_RSA(Pointer var1, int var2, int var3, byte[] var4, int var5, byte[] var6, IntByReference var7);

    int SDF_ExternalSign_ECC(Pointer var1, int var2, SM2refPrivateKey var3, byte[] var4, int var5, SM2refSignature var6);

    int SDF_ExternalVerify_ECC(Pointer var1, int var2, SM2refPublicKey var3, byte[] var4, int var5, SM2refSignature var6);

    int SDF_InternalSign_ECC(Pointer var1, int var2, byte[] var3, int var4, SM2refSignature var5);

    int SDF_InternalVerify_ECC(Pointer var1, int var2, byte[] var3, int var4, SM2refSignature var5);

    int SDF_ExternalEncrypt_ECC(Pointer var1, int var2, SM2refPublicKey var3, byte[] var4, int var5, SM2refCipher var6);

    int SDF_ExternalDecrypt_ECC(Pointer var1, int var2, SM2refPrivateKey var3, SM2refCipher var4, byte[] var5, IntByReference var6);

    int SDF_InternalEncrypt_ECC(Pointer var1, int var2, int var3, byte[] var4, int var5, SM2refCipher var6);

    int SDF_InternalDecrypt_ECC(Pointer var1, int var2, int var3, SM2refCipher var4, byte[] var5, IntByReference var6);

    int SDF_Encrypt(Pointer var1, Pointer var2, int var3, byte[] var4, byte[] var5, int var6, byte[] var7, IntByReference var8);

    int SDF_Decrypt(Pointer var1, Pointer var2, int var3, byte[] var4, byte[] var5, int var6, byte[] var7, IntByReference var8);

    int SDF_CalculateMAC(Pointer var1, Pointer var2, int var3, byte[] var4, byte[] var5, int var6, byte[] var7, IntByReference var8);

    int SDF_HashInit(Pointer var1, int var2, SM2refPublicKey var3, byte[] var4, int var5);

    int SDF_HashUpdate(Pointer var1, byte[] var2, int var3);

    int SDF_HashFinal(Pointer var1, byte[] var2, IntByReference var3);

    int SDF_CreateFile(Pointer var1, byte[] var2, int var3, int var4);

    int SDF_ReadFile(Pointer var1, byte[] var2, int var3, int var4, IntByReference var5, byte[] var6);

    int SDF_WriteFile(Pointer var1, byte[] var2, int var3, int var4, int var5, byte[] var6);

    int SDF_DeleteFile(Pointer var1, byte[] var2, int var3);

    int SDF_InternalSign_ECC_Ex(Pointer var1, int var2, int var3, byte[] var4, int var5, SM2refSignature var6);

    int SDF_InternalVerify_ECC_Ex(Pointer var1, int var2, int var3, byte[] var4, int var5, SM2refSignature var6);

    int SDF_GetSymmKeyHandle(Pointer var1, int var2, PointerByReference var3);

    int SDF_ExportSignPublicKey_ECDSA(Pointer var1, int var2, ECDSArefPublicKey var3);

    int SDF_ExportEncPublicKey_ECDSA(Pointer var1, int var2, ECDSArefPublicKey var3);

    int SDF_GenerateKeyPair_ECDSA(Pointer var1, int var2, int var3, int var4, ECDSArefPublicKey var5, ECDSArefPrivateKey var6);

    int SDF_InternalSign_ECDSA(Pointer var1, int var2, int var3, byte[] var4, int var5, byte[] var6, IntByReference var7);

    int SDF_InternalVerify_ECDSA(Pointer var1, int var2, int var3, byte[] var4, int var5, ECDSArefSignature var6, int var7);

    int SDF_ExternalSign_ECDSA(Pointer var1, int var2, ECDSArefPrivateKey var3, byte[] var4, int var5, byte[] var6, IntByReference var7);

    int SDF_ExternalVerify_ECDSA(Pointer var1, int var2, ECDSArefPublicKey var3, byte[] var4, int var5, ECDSArefSignature var6, int var7);

}
