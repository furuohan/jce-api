package com.No_N_Name.jce.jna.struct2;

public interface IDSArefPublicKey extends IKeyPair{
    int getBits();

    byte[] getP();

    byte[] getQ();

    byte[] getG();

    byte[] getPubkey();
}
