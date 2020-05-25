package com.No_N_Name.jce.jna.struct2;

public interface IRSArefPublicKey extends IKeyPair{
    int getBits();

    byte[] getM();

    byte[] getE();
}
