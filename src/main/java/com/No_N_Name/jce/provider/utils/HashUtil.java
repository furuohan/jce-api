package com.No_N_Name.jce.provider.utils;

public class HashUtil {
	   public static boolean isRightAlg(int algId) {
		      switch(algId) {
		      case 1:
		      case 2:
		      case 4:
		      case 8:
		      case 16:
		      case 32:
		      case 128:
		         return true;
		      default:
		         return false;
		      }
		   }

		   public static boolean isRightHmacAlg(int algId) {
		      switch(algId) {
		      case 1:
		      case 2:
		      case 4:
		      case 8:
		      case 16:
		      case 32:
		         return true;
		      default:
		         return false;
		      }
		   }

		   public static boolean isRightSHAAlg(int algId) {
		      switch(algId) {
		      case 2:
		      case 4:
		      case 8:
		      case 16:
		      case 32:
		         return true;
		      default:
		         return false;
		      }
		   }
}
