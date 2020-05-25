package com.No_N_Name.jce.provider.RSA;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import com.No_N_Name.jce.jna.struct2.IRSArefPublicKey;
import com.No_N_Name.jce.provider.utils.BigIntegerUitl;
import com.No_N_Name.jce.provider.utils.BytesUtil;
import com.No_N_Name.jce.provider.utils.Strings;


public class JCERSAPublicKey implements RSAPublicKey{
    static final long serialVersionUID = 2675817738516720772L;
    private BigInteger modulus;			//ģN
    private BigInteger publicExponent;	//��Կָ��
    private int keyIndex;				//����Internal����External
    private int keyType;				//Internalר������
    private int bits;					//ģ��
    
    
    
    public JCERSAPublicKey(IRSArefPublicKey rsArefPublicKey) {
    	//��������
    	this.bits = (int)rsArefPublicKey.getBits();
    	this.modulus = BigIntegerUitl.toPositiveInteger(rsArefPublicKey.getM());
    	this.publicExponent = BigIntegerUitl.toPositiveInteger(rsArefPublicKey.getE());
    	
    }
    
    public String toString() {
    	 StringBuffer buf = new StringBuffer();
         String nl = Strings.lineSeparator();
         buf.append("RSA Public Key").append(nl);
         buf.append("bits: ").append(this.bits).append(nl);
         buf.append("modulus: ").append(this.getModulus().toString(16)).append(nl);
         buf.append("public exponent: ").append(this.getPublicExponent().toString(16)).append(nl);
         return buf.toString();
    }
	@Override
	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return "RSA";
	}

	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger getModulus() {
		// TODO Auto-generated method stub
		return this.modulus;
	}

	@Override
	public BigInteger getPublicExponent() {
		// TODO Auto-generated method stub
		return this.publicExponent;
	}
	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}

}
