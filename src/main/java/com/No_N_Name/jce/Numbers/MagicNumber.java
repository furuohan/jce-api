package com.No_N_Name.jce.Numbers;

public class MagicNumber {
	public static long SGD_API_VERSION = 0x01000000;
	
	
	public static int LiteRSAref_MAX_BITS = 2048;
	public static int LiteRSAref_MAX_LEN = ((LiteRSAref_MAX_BITS + 7) / 8);
	public static int LiteRSAref_MAX_PBITS = ((LiteRSAref_MAX_BITS + 1) / 2);
	public static int LiteRSAref_MAX_PLEN = ((LiteRSAref_MAX_PBITS + 7) / 8);
	
	
	public static int RSAref_MAX_BITS = 2048;
	public static int RSAref_MAX_LEN = ((RSAref_MAX_BITS + 7) / 8);
	public static int RSAref_MAX_PBITS = ((RSAref_MAX_BITS + 1) / 2);
	public static int RSAref_MAX_PLEN = ((RSAref_MAX_PBITS + 7) / 8);
	
	
	public static int ExRSAref_MAX_BITS = 4096;
	public static int ExRSAref_MAX_LEN = ((ExRSAref_MAX_BITS + 7) / 8);
	public static int ExRSAref_MAX_PBITS = ((ExRSAref_MAX_BITS + 1) / 2);
	public static int ExRSAref_MAX_PLEN = ((ExRSAref_MAX_PBITS + 7) / 8);
	
	
	/*ECC√‹‘ø*/
	public static int ECCref_MAX_BITS = 256;
	public static int ECCref_MAX_LEN = ((ECCref_MAX_BITS + 7) / 8);
	public static int ECCref_MAX_CIPHER_LEN = 136;
	
	
	
}
