package com.No_N_Name.jce.provider.RSA;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;

import com.No_N_Name.jce.jna.struct2.IRSArefPrivateKey;
import com.No_N_Name.jce.provider.utils.BigIntegerUitl;
import com.No_N_Name.jce.provider.utils.Strings;



public class JCERSAPrivateKey implements RSAPrivateKey,RSAPrivateCrtKey{
	static final long serialVersionUID = 7834723820638524718L;
	
	private BigInteger publicExponent;		//e,公钥指数
	private BigInteger primeP;				//prime二维数组存放
	private BigInteger primeQ;				//prime二维数组存放
	private BigInteger primeExponentP;		//pexp二维数组存放
	private BigInteger primeExponentQ;		//pexp二维数组存放
	private BigInteger crtCoefficient;		//coef char数组存放
    private static BigInteger ZERO = BigInteger.valueOf(0L);
    protected BigInteger modulus;			//M，模N
    protected BigInteger privateExponent;	//d，私钥指数
    private int keyIndex;
    private int keyType;
    private int bits;						//bits
    
    public JCERSAPrivateKey(IRSArefPrivateKey rsArefPrivateKey) {
    	//参数传递
    	this.modulus = BigIntegerUitl.toPositiveInteger(rsArefPrivateKey.getM());
    	this.publicExponent = BigIntegerUitl.toPositiveInteger(rsArefPrivateKey.getE());
    	this.bits = (int)rsArefPrivateKey.getBits();
    	this.primeExponentP = BigIntegerUitl.toPositiveInteger(rsArefPrivateKey.getPrime1());
    	this.primeExponentQ = BigIntegerUitl.toPositiveInteger(rsArefPrivateKey.getPrime2());
    	this.primeP = BigIntegerUitl.toPositiveInteger(rsArefPrivateKey.getPexp1());
    	this.primeQ = BigIntegerUitl.toPositiveInteger(rsArefPrivateKey.getPexp2());
    	this.privateExponent = BigIntegerUitl.toPositiveInteger(rsArefPrivateKey.getD());
    	this.crtCoefficient = BigIntegerUitl.toPositiveInteger(rsArefPrivateKey.getCoef());
    }
    public String toString() {
    	  if (this.keyIndex == 0) {
    	         StringBuffer buf = new StringBuffer();
    	         String nl = Strings.lineSeparator();
    	         buf.append("External RSA Private CRT Key").append(nl);
    	         buf.append("bits:").append(this.bits).append(nl);
    	         buf.append("modulus: ").append(this.getModulus().toString(16)).append(nl);
    	         buf.append("public exponent: ").append(this.getPublicExponent().toString(16)).append(nl);
    	         buf.append("private exponent: ").append(this.getPrivateExponent().toString(16)).append(nl);
    	         buf.append("primeP: ").append(this.getPrimeP().toString(16)).append(nl);
    	         buf.append("primeQ: ").append(this.getPrimeQ().toString(16)).append(nl);
    	         buf.append("primeExponentP: ").append(this.getPrimeExponentP().toString(16)).append(nl);
    	         buf.append("primeExponentQ: ").append(this.getPrimeExponentQ().toString(16)).append(nl);
    	         buf.append("crtCoefficient: ").append(this.getCrtCoefficient().toString(16)).append(nl);
    	         return buf.toString();
    	      } else {
    	         return "Internal RSA PrivateKey[ KeyIndex = " + this.keyIndex + ", KeyType = " + this.keyType + ",Bits=" + this.bits + " ]";
    	      }
    }
    
	public int getKeyIndex() {
		return 0;
	}

	public int getKeyType() {
		return 0;
	}

	public int getBits() {
		return 0;
	}

	@Override
	public String getAlgorithm() {
		return "RSA";
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public byte[] getEncoded() {
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
	public BigInteger getPrimeP() {
		// TODO Auto-generated method stub
		return this.primeP;
	}

	@Override
	public BigInteger getPrimeQ() {
		// TODO Auto-generated method stub
		return this.primeQ;
	}

	@Override
	public BigInteger getPrimeExponentP() {
		// TODO Auto-generated method stub
		return this.primeExponentP;
	}

	@Override
	public BigInteger getPrimeExponentQ() {
		// TODO Auto-generated method stub
		return this.primeExponentQ;
	}

	@Override
	public BigInteger getCrtCoefficient() {
		// TODO Auto-generated method stub
		return this.crtCoefficient;
	}

	@Override
	public BigInteger getPrivateExponent() {
		// TODO Auto-generated method stub
		return this.privateExponent;
	}

}
