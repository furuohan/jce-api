package com.No_N_Name.jce.jna.struct2;

public interface IDSArefPrivateKey {
    int getBits();

    byte[] getP();

    byte[] getQ();

    byte[] getG();

    byte[] getPrivkey();

    byte[] getPubkey();
}
