package com.No_N_Name.jce.Numbers;

public class MagicNumber_two {
	public static long SGD_API_VERSION = 0x01000000;

/*常量定义*/
public static long SGD_TRUE =0x00000001;
public static long SGD_FALSE =0x00000000;

/*算法标识*/
public static long SGD_SM1_ECB =0x00000101;
public static long SGD_SM1_CBC =0x00000102;
public static long SGD_SM1_CFB =0x00000104;
public static long SGD_SM1_OFB =0x00000108;
public static long SGD_SM1_MAC =0x00000110;

public static long SGD_SSF33_ECB= 0x00000201;
public static long SGD_SSF33_CBC =0x00000202;
public static long SGD_SSF33_CFB =0x00000204;
public static long SGD_SSF33_OFB =0x00000208;
public static long SGD_SSF33_MAC =0x00000210;

public static long SGD_AES_ECB= 0x00000401;
public static long SGD_AES_CBC =0x00000402;
public static long SGD_AES_CFB =0x00000404;
public static long SGD_AES_OFB =0x00000408;
public static long SGD_AES_MAC =0x00000410;

public static long SGD_3DES_ECB= 0x00000801;
public static long SGD_3DES_CBC= 0x00000802;
public static long SGD_3DES_CFB= 0x00000804;
public static long SGD_3DES_OFB= 0x00000808;
public static long SGD_3DES_MAC= 0x00000810;

public static long SGD_SMS4_ECB= 0x00002001;
public static long SGD_SMS4_CBC =0x00002002;
public static long SGD_SMS4_CFB= 0x00002004;
public static long SGD_SMS4_OFB= 0x00002008;
public static long SGD_SMS4_MAC= 0x00002010;

public static long SGD_DES_ECB =0x00004001;
public static long SGD_DES_CBC =0x00004002;
public static long SGD_DES_CFB= 0x00004004;
public static long SGD_DES_OFB =0x00004008;
public static long SGD_DES_MAC =0x00004010;

public static long SGD_RSA= 0x00010000;
public static long SGD_RSA_SIGN= 0x00010100;
public static long SGD_RSA_ENC= 0x00010200;
public static long SGD_SM2_1= 0x00020100;
public static long SGD_SM2_2= 0x00020200;
public static long SGD_SM2_3= 0x00020400;

public static long SGD_SM3 =0x00000001;
public static long SGD_SHA1 =0x00000002;
public static long SGD_SHA256 =0x00000004;
public static long SGD_SHA512 =0x00000008;
public static long SGD_SHA384 =0x00000010;
public static long SGD_SHA224 =0x00000020;
public static long SGD_MD5 =0x00000080;

/*标准错误码定义*/
public static long SDR_OK =0x0; /*成功*/
public static long SDR_BASE =0x01000000;
public static long SDR_UNKNOWERR =(SDR_BASE + 0x00000001);     /*未知错误*/
public static long SDR_NOTSUPPORT =(SDR_BASE + 0x00000002);    /*不支持*/
public static long SDR_COMMFAIL =(SDR_BASE + 0x00000003);      /*通信错误*/
public static long SDR_HARDFAIL =(SDR_BASE + 0x00000004);      /*硬件错误*/
public static long SDR_OPENDEVICE =(SDR_BASE + 0x00000005);    /*打开设备错误*/
public static long SDR_OPENSESSION= (SDR_BASE + 0x00000006);   /*打开会话句柄错误*/
public static long SDR_PARDENY =(SDR_BASE + 0x00000007);       /*权限不满足*/
public static long SDR_KEYNOTEXIST= (SDR_BASE + 0x00000008);   /*密钥不存在*/
public static long SDR_ALGNOTSUPPORT =(SDR_BASE + 0x00000009); /*不支持的算法*/
public static long SDR_ALGMODNOTSUPPORT =(SDR_BASE + 0x0000000A); /*不支持的算法模式*/
public static long SDR_PKOPERR= (SDR_BASE + 0x0000000B);          /*公钥运算错误*/
public static long SDR_SKOPERR =(SDR_BASE + 0x0000000C);          /*私钥运算错误*/
public static long SDR_SIGNERR= (SDR_BASE + 0x0000000D);          /*签名错误*/
public static long SDR_VERIFYERR =(SDR_BASE + 0x0000000E);        /*验证错误*/
public static long SDR_SYMOPERR =(SDR_BASE + 0x0000000F);         /*对称运算错误*/
public static long SDR_STEPERR= (SDR_BASE + 0x00000010);          /*步骤错误*/
public static long SDR_FILESIZEERR=(SDR_BASE + 0x00000011); /*文件大小错误或输入数据长度非法*/
public static long SDR_FILENOEXIST =(SDR_BASE + 0x00000012); /*文件不存在*/
public static long SDR_FILEOFSERR =(SDR_BASE + 0x00000013);  /*文件操作偏移量错误*/
public static long SDR_KEYTYPEERR =(SDR_BASE + 0x00000014);  /*密钥类型错误*/
public static long SDR_KEYERR =(SDR_BASE + 0x00000015);      /*密钥错误*/

/*============================================================*/
/*扩展错误码*/
public static long SWR_BASE =(SDR_BASE + 0x00010000);         /*自定义错误码基础值*/
public static long SWR_INVALID_USER =(SWR_BASE + 0x00000001); /*无效的用户名*/
public static long SWR_INVALID_AUTHENCODE =(SWR_BASE + 0x00000002); /*无效的授权码*/
public static long SWR_PROTOCOL_VER_ERR =(SWR_BASE + 0x00000003); /*不支持的协议版本*/
public static long SWR_INVALID_COMMAND =(SWR_BASE + 0x00000004);  /*错误的命令字*/
public static long SWR_INVALID_PARAMETERS =(SWR_BASE + 0x00000005); /*参数错误或错误的数据包格式*/
public static long SWR_FILE_ALREADY_EXIST =(SWR_BASE + 0x00000006); /*已存在同名文件*/
public static long SWR_SYNCH_ERR =(SWR_BASE + 0x00000007);          /*多卡同步错误*/
public static long SWR_SYNCH_LOGIN_ERR =(SWR_BASE + 0x00000008); /*多卡同步后登录错误*/

public static long SWR_SOCKET_TIMEOUT =(SWR_BASE + 0x00000100);  /*超时错误*/
public static long SWR_CONNECT_ERR =(SWR_BASE + 0x00000101);     /*连接服务器错误*/
public static long SWR_SET_SOCKOPT_ERR =(SWR_BASE + 0x00000102); /*设置Socket参数错误*/
public static long SWR_SOCKET_SEND_ERR =(SWR_BASE + 0x00000104); /*发送LOGINRequest错误*/
public static long SWR_SOCKET_RECV_ERR =(SWR_BASE + 0x00000105); /*发送LOGINRequest错误*/
public static long SWR_SOCKET_RECV_0 =(SWR_BASE + 0x00000106);   /*发送LOGINRequest错误*/

public static long SWR_SEM_TIMEOUT =(SWR_BASE + 0x00000200);      /*超时错误*/
public static long SWR_NO_AVAILABLE_HSM =(SWR_BASE + 0x00000201); /*没有可用的加密机*/
public static long SWR_NO_AVAILABLE_CSM =(SWR_BASE + 0x00000202); /*加密机内没有可用的加密模块*/

public static long SWR_CONFIG_ERR =(SWR_BASE + 0x00000301); /*配置文件错误*/

/*============================================================*/
/*密码卡错误码*/
public static long SWR_CARD_BASE= (SDR_BASE + 0x00020000);           /*密码卡错误码*/
public static long SWR_CARD_UNKNOWERR =(SWR_CARD_BASE + 0x00000001); //未知错误
public static long SWR_CARD_NOTSUPPORT =(SWR_CARD_BASE + 0x00000002); //不支持的接口调用
public static long SWR_CARD_COMMFAIL =(SWR_CARD_BASE + 0x00000003);   //与设备通信失败
public static long SWR_CARD_HARDFAIL= (SWR_CARD_BASE + 0x00000004);   //运算模块无响应
public static long SWR_CARD_OPENDEVICE =(SWR_CARD_BASE + 0x00000005); //打开设备失败
public static long SWR_CARD_OPENSESSION =(SWR_CARD_BASE + 0x00000006); //创建会话失败
public static long SWR_CARD_PARDENY =(SWR_CARD_BASE + 0x00000007); //无私钥使用权限
public static long SWR_CARD_KEYNOTEXIST =(SWR_CARD_BASE + 0x00000008); //不存在的密钥调用
public static long SWR_CARD_ALGNOTSUPPORT =(SWR_CARD_BASE + 0x00000009); //不支持的算法调用
public static long SWR_CARD_ALGMODNOTSUPPORT =(SWR_CARD_BASE + 0x00000010);                        //不支持的算法调用
public static long SWR_CARD_PKOPERR =(SWR_CARD_BASE + 0x00000011); //公钥运算失败
public static long SWR_CARD_SKOPERR =(SWR_CARD_BASE + 0x00000012); //私钥运算失败
public static long SWR_CARD_SIGNERR =(SWR_CARD_BASE + 0x00000013); //签名运算失败
public static long SWR_CARD_VERIFYERR =(SWR_CARD_BASE + 0x00000014); //验证签名失败
public static long SWR_CARD_SYMOPERR= (SWR_CARD_BASE + 0x00000015); //对称算法运算失败
public static long SWR_CARD_STEPERR= (SWR_CARD_BASE + 0x00000016); //多步运算步骤错误
public static long SWR_CARD_FILESIZEERR =(SWR_CARD_BASE + 0x00000017); //文件长度超出限制
public static long SWR_CARD_FILENOEXIST =(SWR_CARD_BASE + 0x00000018); //指定的文件不存在
public static long SWR_CARD_FILEOFSERR =(SWR_CARD_BASE + 0x00000019); //文件起始位置错误
public static long SWR_CARD_KEYTYPEERR =(SWR_CARD_BASE + 0x00000020); //密钥类型错误
public static long SWR_CARD_KEYERR =(SWR_CARD_BASE + 0x00000021);     //密钥错误
public static long SWR_CARD_BUFFER_TOO_SMALL=(SWR_CARD_BASE + 0x00000101); //接收参数的缓存区太小
public static long SWR_CARD_DATA_PAD  =(SWR_CARD_BASE +  0x00000102); //数据没有按正确格式填充，或解密得到的脱密数据不符合填充格式
public static long SWR_CARD_DATA_SIZE=(SWR_CARD_BASE + 0x00000103); //明文或密文长度不符合相应的算法要求
public static long SWR_CARD_CRYPTO_NOT_INIT=(SWR_CARD_BASE + 0x00000104); //该错误表明没有为相应的算法调用初始化函数

// 01/03/09版密码卡权限管理错误码
public static long SWR_CARD_MANAGEMENT_DENY =(SWR_CARD_BASE + 0x00001001); //管理权限不满足
public static long SWR_CARD_OPERATION_DENY =(SWR_CARD_BASE + 0x00001002);//操作权限不满足
public static long SWR_CARD_DEVICE_STATUS_ERR =(SWR_CARD_BASE + 0x00001003); //当前设备状态不满足现有操作
public static long SWR_CARD_LOGIN_ERR =(SWR_CARD_BASE + 0x00001011); //登录失败
public static long SWR_CARD_USERID_ERR =(SWR_CARD_BASE + 0x00001012); //用户ID数目/号码错误
public static long SWR_CARD_PARAMENT_ERR =(SWR_CARD_BASE + 0x00001013); //参数错误

// 05/06版密码卡权限管理错误码
public static long SWR_CARD_MANAGEMENT_DENY_05 = (SWR_CARD_BASE + 0x00000801); //管理权限不满足
public static long SWR_CARD_OPERATION_DENY_05 =(SWR_CARD_BASE + 0x00000802); //操作权限不满足
public static long SWR_CARD_DEVICE_STATUS_ERR_05 = (SWR_CARD_BASE + 0x00000803); //当前设备状态不满足现有操作
public static long SWR_CARD_LOGIN_ERR_05 =(SWR_CARD_BASE + 0x00000811); //登录失败
public static long SWR_CARD_USERID_ERR_05 = (SWR_CARD_BASE + 0x00000812); //用户ID数目/号码错误
public static long SWR_CARD_PARAMENT_ERR_05 =(SWR_CARD_BASE + 0x00000813); //参数错误

/*============================================================*/
/*读卡器错误*/
public static long SWR_CARD_READER_BASE =(SDR_BASE + 0x00030000); //	读卡器类型错误
public static long SWR_CARD_READER_PIN_ERROR= (SWR_CARD_READER_BASE + 0x000063CE); //口令错误
public static long SWR_CARD_READER_NO_CARD =(SWR_CARD_READER_BASE + 0x0000FF01); //	IC未插入
public static long SWR_CARD_READER_CARD_INSERT = (SWR_CARD_READER_BASE + 0x0000FF02); //	IC插入方向错误或不到位
public static long SWR_CARD_READER_CARD_INSERT_TYPE =(SWR_CARD_READER_BASE + 0x0000FF03); //	IC类型错误

}
