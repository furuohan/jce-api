package com.No_N_Name.jce.jna.api;

public class CryptoException extends Exception{
	  private static final long serialVersionUID = 1L;

	    public CryptoException() {
	    }

	    public CryptoException(String msg) {
	        super(msg);
	    }

	    public CryptoException(String message, Throwable cause) {
	        super(message, cause);
	    }

	    public CryptoException(Throwable cause) {
	        super(cause);
	    }
}
