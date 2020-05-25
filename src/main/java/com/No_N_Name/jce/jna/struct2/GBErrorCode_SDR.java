package com.No_N_Name.jce.jna.struct2;
import java.lang.reflect.Field;

public class GBErrorCode_SDR {
	   public static int SDR_OK = 0;
	   public static int SDR_BASE = 16777216;
	   public static int SDR_UNKNOWERR;
	   public static int SDR_NOTSUPPORT;
	   public static int SDR_COMMFAIL;
	   public static int SDR_HARDFAIL;
	   public static int SDR_OPENDEVICE;
	   public static int SDR_OPENSESSION;
	   public static int SDR_PARDENY;
	   public static int SDR_KEYNOTEXIST;
	   public static int SDR_ALGNOTSUPPORT;
	   public static int SDR_ALGMODNOTSUPPORT;
	   public static int SDR_PKOPERR;
	   public static int SDR_SKOPERR;
	   public static int SDR_SIGNERR;
	   public static int SDR_VERIFYERR;
	   public static int SDR_SYMOPERR;
	   public static int SDR_STEPERR;
	   public static int SDR_FILESIZEERR;
	   public static int SDR_FILENOEXIST;
	   public static int SDR_FILEOFSERR;
	   public static int SDR_KEYTYPEERR;
	   public static int SDR_KEYERR;
	   public static int SWR_BASE;
	   public static int SWR_INVALID_USER;
	   public static int SWR_INVALID_AUTHENCODE;
	   public static int SWR_PROTOCOL_VER_ERR;
	   public static int SWR_INVALID_COMMAND;
	   public static int SWR_INVALID_PARAMETERS;
	   public static int SWR_FILE_ALREADY_EXIST;
	   public static int SWR_SOCKET_TIMEOUT;
	   public static int SWR_CONNECT_ERR;
	   public static int SWR_SET_SOCKOPT_ERR;
	   public static int SWR_SOCKET_SEND_ERR;
	   public static int SWR_SOCKET_RECV_ERR;
	   public static int SWR_SOCKET_RECV_0;
	   public static int SWR_SEM_TIMEOUT;
	   public static int SWR_NO_VALID_HSM;
	   public static int SWR_CONFIG_ERR;
	   public static int USER_KEY_NOT_EXISTS_ERR;
	   public static int SWR_CARD_BASE;
	   public static int SWR_CARD_UNKNOWERR;
	   public static int SWR_CARD_NOTSUPPORT;
	   public static int SWR_CARD_COMMFAIL;
	   public static int SWR_CARD_HARDFAIL;
	   public static int SWR_CARD_OPENDEVICE;
	   public static int SWR_CARD_OPENSESSION;
	   public static int SWR_CARD_PARDENY;
	   public static int SWR_CARD_KEYNOTEXIST;
	   public static int SWR_CARD_ALGNOTSUPPORT;
	   public static int SWR_CARD_ALGMODNOTSUPPORT;
	   public static int SWR_CARD_PKOPERR;
	   public static int SWR_CARD_SKOPERR;
	   public static int SWR_CARD_SIGNERR;
	   public static int SWR_CARD_VERIFYERR;
	   public static int SWR_CARD_SYMOPERR;
	   public static int SWR_CARD_STEPERR;
	   public static int SWR_CARD_FILESIZEERR;
	   public static int SWR_CARD_FILENOEXIST;
	   public static int SWR_CARD_FILEOFSERR;
	   public static int SWR_CARD_KEYTYPEERR;
	   public static int SWR_CARD_KEYERR;
	   public static int SWR_CARD_BUFFER_TOO_SMALL;
	   public static int SWR_CARD_DATA_PAD;
	   public static int SWR_CARD_DATA_SIZE;
	   public static int SWR_CARD_CRYPTO_NOT_INIT;
	   public static int SWR_CARD_MANAGEMENT_DENY;
	   public static int SWR_CARD_OPERATION_DENY;
	   public static int SWR_CARD_DEVICE_STATUS_ERR;
	   public static int SWR_CARD_LOGIN_ERR;
	   public static int SWR_CARD_USERID_ERR;
	   public static int SWR_CARD_PARAMENT_ERR;
	   public static int SWR_CARD_MANAGEMENT_DENY_05;
	   public static int SWR_CARD_OPERATION_DENY_05;
	   public static int SWR_CARD_DEVICE_STATUS_ERR_05;
	   public static int SWR_CARD_LOGIN_ERR_05;
	   public static int SWR_CARD_USERID_ERR_05;
	   public static int SWR_CARD_PARAMENT_ERR_05;
	   public static int SWR_CARD_READER_BASE;
	   public static int SWR_CARD_READER_PIN_ERROR;
	   public static int SWR_CARD_READER_NO_CARD;
	   public static int SWR_CARD_READER_CARD_INSERT;
	   public static int SWR_CARD_READER_CARD_INSERT_TYPE;

	   public static String toErrorInfo(int errorCode) {
	      GBErrorCode_SDR instance = new GBErrorCode_SDR();
	      Field[] fields = instance.getClass().getDeclaredFields();

	      for(int i = 0; i < fields.length; ++i) {
	         try {
	            if (fields[i].get(instance).equals(errorCode)) {
	               return fields[i].getName() + ":" + Integer.toHexString(errorCode);
	            }
	         } catch (IllegalAccessException var5) {
	            var5.printStackTrace();
	         }
	      }

	      return "Unknown Error:" + Integer.toHexString(errorCode);
	   }

	   static {
	      SDR_UNKNOWERR = SDR_BASE + 1;
	      SDR_NOTSUPPORT = SDR_BASE + 2;
	      SDR_COMMFAIL = SDR_BASE + 3;
	      SDR_HARDFAIL = SDR_BASE + 4;
	      SDR_OPENDEVICE = SDR_BASE + 5;
	      SDR_OPENSESSION = SDR_BASE + 6;
	      SDR_PARDENY = SDR_BASE + 7;
	      SDR_KEYNOTEXIST = SDR_BASE + 8;
	      SDR_ALGNOTSUPPORT = SDR_BASE + 9;
	      SDR_ALGMODNOTSUPPORT = SDR_BASE + 10;
	      SDR_PKOPERR = SDR_BASE + 11;
	      SDR_SKOPERR = SDR_BASE + 12;
	      SDR_SIGNERR = SDR_BASE + 13;
	      SDR_VERIFYERR = SDR_BASE + 14;
	      SDR_SYMOPERR = SDR_BASE + 15;
	      SDR_STEPERR = SDR_BASE + 16;
	      SDR_FILESIZEERR = SDR_BASE + 17;
	      SDR_FILENOEXIST = SDR_BASE + 18;
	      SDR_FILEOFSERR = SDR_BASE + 19;
	      SDR_KEYTYPEERR = SDR_BASE + 20;
	      SDR_KEYERR = SDR_BASE + 21;
	      SWR_BASE = SDR_BASE + 65536;
	      SWR_INVALID_USER = SWR_BASE + 1;
	      SWR_INVALID_AUTHENCODE = SWR_BASE + 2;
	      SWR_PROTOCOL_VER_ERR = SWR_BASE + 3;
	      SWR_INVALID_COMMAND = SWR_BASE + 4;
	      SWR_INVALID_PARAMETERS = SWR_BASE + 5;
	      SWR_FILE_ALREADY_EXIST = SWR_BASE + 6;
	      SWR_SOCKET_TIMEOUT = SWR_BASE + 256;
	      SWR_CONNECT_ERR = SWR_BASE + 257;
	      SWR_SET_SOCKOPT_ERR = SWR_BASE + 258;
	      SWR_SOCKET_SEND_ERR = SWR_BASE + 260;
	      SWR_SOCKET_RECV_ERR = SWR_BASE + 261;
	      SWR_SOCKET_RECV_0 = SWR_BASE + 262;
	      SWR_SEM_TIMEOUT = SWR_BASE + 513;
	      SWR_NO_VALID_HSM = SWR_BASE + 514;
	      SWR_CONFIG_ERR = SWR_BASE + 769;
	      USER_KEY_NOT_EXISTS_ERR = 16908296;
	      SWR_CARD_BASE = SDR_BASE + 131072;
	      SWR_CARD_UNKNOWERR = SWR_CARD_BASE + 1;
	      SWR_CARD_NOTSUPPORT = SWR_CARD_BASE + 2;
	      SWR_CARD_COMMFAIL = SWR_CARD_BASE + 3;
	      SWR_CARD_HARDFAIL = SWR_CARD_BASE + 4;
	      SWR_CARD_OPENDEVICE = SWR_CARD_BASE + 5;
	      SWR_CARD_OPENSESSION = SWR_CARD_BASE + 6;
	      SWR_CARD_PARDENY = SWR_CARD_BASE + 7;
	      SWR_CARD_KEYNOTEXIST = SWR_CARD_BASE + 8;
	      SWR_CARD_ALGNOTSUPPORT = SWR_CARD_BASE + 9;
	      SWR_CARD_ALGMODNOTSUPPORT = SWR_CARD_BASE + 16;
	      SWR_CARD_PKOPERR = SWR_CARD_BASE + 17;
	      SWR_CARD_SKOPERR = SWR_CARD_BASE + 18;
	      SWR_CARD_SIGNERR = SWR_CARD_BASE + 19;
	      SWR_CARD_VERIFYERR = SWR_CARD_BASE + 20;
	      SWR_CARD_SYMOPERR = SWR_CARD_BASE + 21;
	      SWR_CARD_STEPERR = SWR_CARD_BASE + 22;
	      SWR_CARD_FILESIZEERR = SWR_CARD_BASE + 23;
	      SWR_CARD_FILENOEXIST = SWR_CARD_BASE + 24;
	      SWR_CARD_FILEOFSERR = SWR_CARD_BASE + 25;
	      SWR_CARD_KEYTYPEERR = SWR_CARD_BASE + 32;
	      SWR_CARD_KEYERR = SWR_CARD_BASE + 33;
	      SWR_CARD_BUFFER_TOO_SMALL = SWR_CARD_BASE + 257;
	      SWR_CARD_DATA_PAD = SWR_CARD_BASE + 258;
	      SWR_CARD_DATA_SIZE = SWR_CARD_BASE + 259;
	      SWR_CARD_CRYPTO_NOT_INIT = SWR_CARD_BASE + 260;
	      SWR_CARD_MANAGEMENT_DENY = SWR_CARD_BASE + 4097;
	      SWR_CARD_OPERATION_DENY = SWR_CARD_BASE + 4098;
	      SWR_CARD_DEVICE_STATUS_ERR = SWR_CARD_BASE + 4099;
	      SWR_CARD_LOGIN_ERR = SWR_CARD_BASE + 4113;
	      SWR_CARD_USERID_ERR = SWR_CARD_BASE + 4114;
	      SWR_CARD_PARAMENT_ERR = SWR_CARD_BASE + 4115;
	      SWR_CARD_MANAGEMENT_DENY_05 = SWR_CARD_BASE + 2049;
	      SWR_CARD_OPERATION_DENY_05 = SWR_CARD_BASE + 2050;
	      SWR_CARD_DEVICE_STATUS_ERR_05 = SWR_CARD_BASE + 2051;
	      SWR_CARD_LOGIN_ERR_05 = SWR_CARD_BASE + 2065;
	      SWR_CARD_USERID_ERR_05 = SWR_CARD_BASE + 2066;
	      SWR_CARD_PARAMENT_ERR_05 = SWR_CARD_BASE + 2067;
	      SWR_CARD_READER_BASE = SDR_BASE + 196608;
	      SWR_CARD_READER_PIN_ERROR = SWR_CARD_READER_BASE + 25550;
	      SWR_CARD_READER_NO_CARD = SWR_CARD_READER_BASE + '£¡';
	      SWR_CARD_READER_CARD_INSERT = SWR_CARD_READER_BASE + '£¢';
	      SWR_CARD_READER_CARD_INSERT_TYPE = SWR_CARD_READER_BASE + '££';
	   }
}
