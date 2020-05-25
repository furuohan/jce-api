package com.No_N_Name.jce.jna.struct2;

public interface IRSArefPrivateKey extends IKeyPair{
    int getBits();

    byte[] getM();

    byte[] getE();

    byte[] getD();

    byte[] getPrime1();

    byte[] getPrime2();

    byte[] getPexp1();

    byte[] getPexp2();

    byte[] getCoef();
}
