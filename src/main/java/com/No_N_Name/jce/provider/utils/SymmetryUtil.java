package com.No_N_Name.jce.provider.utils;

public class SymmetryUtil {
	   public static boolean isRightAlg(int algType) {
		      boolean flag = false;
		      switch(algType) {
		      case 257:
		      case 258:
		      case 260:
		      case 264:
		      case 272:
		      case 288:
		      case 513:
		      case 514:
		      case 516:
		      case 520:
		      case 528:
		      case 544:
		      case 1025:
		      case 1026:
		      case 1028:
		      case 1032:
		      case 1040:
		      case 1056:
		      case 1088:
		      case 2049:
		      case 2050:
		      case 2052:
		      case 2056:
		      case 2064:
		      case 2080:
		      case 8193:
		      case 8194:
		      case 8224:
		      case 16385:
		      case 16386:
		      case 16388:
		      case 16392:
		      case 16400:
		      case 16416:
		         flag = true;
		         break;
		      default:
		         flag = false;
		      }

		      return flag;
		   }

		   public static boolean isRightInput(int algType, byte[] input) {
		      if (input != null && 0 != input.length) {
		         boolean flag = false;
		         byte keyLength;
		         switch(algType) {
		         case 257:
		         case 258:
		         case 260:
		         case 264:
		         case 272:
		         case 288:
		         case 513:
		         case 514:
		         case 516:
		         case 520:
		         case 528:
		         case 544:
		         case 1025:
		         case 1026:
		         case 1028:
		         case 1032:
		         case 1040:
		         case 1056:
		         case 1088:
		         case 8193:
		         case 8194:
		         case 8224:
		            keyLength = 16;
		            break;
		         case 2049:
		         case 2050:
		         case 2052:
		         case 2056:
		         case 2064:
		         case 2080:
		         case 16385:
		         case 16386:
		         case 16388:
		         case 16392:
		         case 16400:
		         case 16416:
		            keyLength = 8;
		            break;
		         default:
		            keyLength = 10;
		         }

		         if (input.length % keyLength == 0) {
		            flag = true;
		         }

		         return flag;
		      } else {
		         return false;
		      }
		   }

		   public static boolean isRightIV(int algoType, byte[] iv) {
		      boolean flag = false;
		      int ivLength = 0;
		      switch(algoType) {
		      case 257:
		      case 272:
		      case 288:
		      case 513:
		      case 528:
		      case 544:
		      case 1025:
		      case 1040:
		      case 1056:
		      case 2049:
		      case 2064:
		      case 2080:
		      case 8193:
		      case 8224:
		      case 16385:
		      case 16400:
		      case 16416:
		         flag = true;
		         break;
		      case 258:
		      case 260:
		      case 264:
		      case 514:
		      case 516:
		      case 520:
		      case 1026:
		      case 1028:
		      case 1032:
		      case 8194:
		         ivLength = 16;
		         if (iv == null || 0 == iv.length) {
		            flag = false;
		         }
		         break;
		      case 1088:
		         flag = true;
		         break;
		      case 2050:
		      case 2052:
		      case 2056:
		      case 16386:
		      case 16388:
		      case 16392:
		         ivLength = 8;
		         if (iv == null || 0 == iv.length) {
		            flag = false;
		         }
		         break;
		      default:
		         ivLength = 10;
		      }

		      if (flag || iv.length % ivLength == 0) {
		         flag = true;
		      }

		      return flag;
		   }
}
