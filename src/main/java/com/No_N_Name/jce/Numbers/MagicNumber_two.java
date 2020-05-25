package com.No_N_Name.jce.Numbers;

public class MagicNumber_two {
	public static long SGD_API_VERSION = 0x01000000;

/*��������*/
public static long SGD_TRUE =0x00000001;
public static long SGD_FALSE =0x00000000;

/*�㷨��ʶ*/
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

/*��׼�����붨��*/
public static long SDR_OK =0x0; /*�ɹ�*/
public static long SDR_BASE =0x01000000;
public static long SDR_UNKNOWERR =(SDR_BASE + 0x00000001);     /*δ֪����*/
public static long SDR_NOTSUPPORT =(SDR_BASE + 0x00000002);    /*��֧��*/
public static long SDR_COMMFAIL =(SDR_BASE + 0x00000003);      /*ͨ�Ŵ���*/
public static long SDR_HARDFAIL =(SDR_BASE + 0x00000004);      /*Ӳ������*/
public static long SDR_OPENDEVICE =(SDR_BASE + 0x00000005);    /*���豸����*/
public static long SDR_OPENSESSION= (SDR_BASE + 0x00000006);   /*�򿪻Ự�������*/
public static long SDR_PARDENY =(SDR_BASE + 0x00000007);       /*Ȩ�޲�����*/
public static long SDR_KEYNOTEXIST= (SDR_BASE + 0x00000008);   /*��Կ������*/
public static long SDR_ALGNOTSUPPORT =(SDR_BASE + 0x00000009); /*��֧�ֵ��㷨*/
public static long SDR_ALGMODNOTSUPPORT =(SDR_BASE + 0x0000000A); /*��֧�ֵ��㷨ģʽ*/
public static long SDR_PKOPERR= (SDR_BASE + 0x0000000B);          /*��Կ�������*/
public static long SDR_SKOPERR =(SDR_BASE + 0x0000000C);          /*˽Կ�������*/
public static long SDR_SIGNERR= (SDR_BASE + 0x0000000D);          /*ǩ������*/
public static long SDR_VERIFYERR =(SDR_BASE + 0x0000000E);        /*��֤����*/
public static long SDR_SYMOPERR =(SDR_BASE + 0x0000000F);         /*�Գ��������*/
public static long SDR_STEPERR= (SDR_BASE + 0x00000010);          /*�������*/
public static long SDR_FILESIZEERR=(SDR_BASE + 0x00000011); /*�ļ���С������������ݳ��ȷǷ�*/
public static long SDR_FILENOEXIST =(SDR_BASE + 0x00000012); /*�ļ�������*/
public static long SDR_FILEOFSERR =(SDR_BASE + 0x00000013);  /*�ļ�����ƫ��������*/
public static long SDR_KEYTYPEERR =(SDR_BASE + 0x00000014);  /*��Կ���ʹ���*/
public static long SDR_KEYERR =(SDR_BASE + 0x00000015);      /*��Կ����*/

/*============================================================*/
/*��չ������*/
public static long SWR_BASE =(SDR_BASE + 0x00010000);         /*�Զ�����������ֵ*/
public static long SWR_INVALID_USER =(SWR_BASE + 0x00000001); /*��Ч���û���*/
public static long SWR_INVALID_AUTHENCODE =(SWR_BASE + 0x00000002); /*��Ч����Ȩ��*/
public static long SWR_PROTOCOL_VER_ERR =(SWR_BASE + 0x00000003); /*��֧�ֵ�Э��汾*/
public static long SWR_INVALID_COMMAND =(SWR_BASE + 0x00000004);  /*�����������*/
public static long SWR_INVALID_PARAMETERS =(SWR_BASE + 0x00000005); /*����������������ݰ���ʽ*/
public static long SWR_FILE_ALREADY_EXIST =(SWR_BASE + 0x00000006); /*�Ѵ���ͬ���ļ�*/
public static long SWR_SYNCH_ERR =(SWR_BASE + 0x00000007);          /*�࿨ͬ������*/
public static long SWR_SYNCH_LOGIN_ERR =(SWR_BASE + 0x00000008); /*�࿨ͬ�����¼����*/

public static long SWR_SOCKET_TIMEOUT =(SWR_BASE + 0x00000100);  /*��ʱ����*/
public static long SWR_CONNECT_ERR =(SWR_BASE + 0x00000101);     /*���ӷ���������*/
public static long SWR_SET_SOCKOPT_ERR =(SWR_BASE + 0x00000102); /*����Socket��������*/
public static long SWR_SOCKET_SEND_ERR =(SWR_BASE + 0x00000104); /*����LOGINRequest����*/
public static long SWR_SOCKET_RECV_ERR =(SWR_BASE + 0x00000105); /*����LOGINRequest����*/
public static long SWR_SOCKET_RECV_0 =(SWR_BASE + 0x00000106);   /*����LOGINRequest����*/

public static long SWR_SEM_TIMEOUT =(SWR_BASE + 0x00000200);      /*��ʱ����*/
public static long SWR_NO_AVAILABLE_HSM =(SWR_BASE + 0x00000201); /*û�п��õļ��ܻ�*/
public static long SWR_NO_AVAILABLE_CSM =(SWR_BASE + 0x00000202); /*���ܻ���û�п��õļ���ģ��*/

public static long SWR_CONFIG_ERR =(SWR_BASE + 0x00000301); /*�����ļ�����*/

/*============================================================*/
/*���뿨������*/
public static long SWR_CARD_BASE= (SDR_BASE + 0x00020000);           /*���뿨������*/
public static long SWR_CARD_UNKNOWERR =(SWR_CARD_BASE + 0x00000001); //δ֪����
public static long SWR_CARD_NOTSUPPORT =(SWR_CARD_BASE + 0x00000002); //��֧�ֵĽӿڵ���
public static long SWR_CARD_COMMFAIL =(SWR_CARD_BASE + 0x00000003);   //���豸ͨ��ʧ��
public static long SWR_CARD_HARDFAIL= (SWR_CARD_BASE + 0x00000004);   //����ģ������Ӧ
public static long SWR_CARD_OPENDEVICE =(SWR_CARD_BASE + 0x00000005); //���豸ʧ��
public static long SWR_CARD_OPENSESSION =(SWR_CARD_BASE + 0x00000006); //�����Ựʧ��
public static long SWR_CARD_PARDENY =(SWR_CARD_BASE + 0x00000007); //��˽Կʹ��Ȩ��
public static long SWR_CARD_KEYNOTEXIST =(SWR_CARD_BASE + 0x00000008); //�����ڵ���Կ����
public static long SWR_CARD_ALGNOTSUPPORT =(SWR_CARD_BASE + 0x00000009); //��֧�ֵ��㷨����
public static long SWR_CARD_ALGMODNOTSUPPORT =(SWR_CARD_BASE + 0x00000010);                        //��֧�ֵ��㷨����
public static long SWR_CARD_PKOPERR =(SWR_CARD_BASE + 0x00000011); //��Կ����ʧ��
public static long SWR_CARD_SKOPERR =(SWR_CARD_BASE + 0x00000012); //˽Կ����ʧ��
public static long SWR_CARD_SIGNERR =(SWR_CARD_BASE + 0x00000013); //ǩ������ʧ��
public static long SWR_CARD_VERIFYERR =(SWR_CARD_BASE + 0x00000014); //��֤ǩ��ʧ��
public static long SWR_CARD_SYMOPERR= (SWR_CARD_BASE + 0x00000015); //�Գ��㷨����ʧ��
public static long SWR_CARD_STEPERR= (SWR_CARD_BASE + 0x00000016); //�ಽ���㲽�����
public static long SWR_CARD_FILESIZEERR =(SWR_CARD_BASE + 0x00000017); //�ļ����ȳ�������
public static long SWR_CARD_FILENOEXIST =(SWR_CARD_BASE + 0x00000018); //ָ�����ļ�������
public static long SWR_CARD_FILEOFSERR =(SWR_CARD_BASE + 0x00000019); //�ļ���ʼλ�ô���
public static long SWR_CARD_KEYTYPEERR =(SWR_CARD_BASE + 0x00000020); //��Կ���ʹ���
public static long SWR_CARD_KEYERR =(SWR_CARD_BASE + 0x00000021);     //��Կ����
public static long SWR_CARD_BUFFER_TOO_SMALL=(SWR_CARD_BASE + 0x00000101); //���ղ����Ļ�����̫С
public static long SWR_CARD_DATA_PAD  =(SWR_CARD_BASE +  0x00000102); //����û�а���ȷ��ʽ��䣬����ܵõ����������ݲ���������ʽ
public static long SWR_CARD_DATA_SIZE=(SWR_CARD_BASE + 0x00000103); //���Ļ����ĳ��Ȳ�������Ӧ���㷨Ҫ��
public static long SWR_CARD_CRYPTO_NOT_INIT=(SWR_CARD_BASE + 0x00000104); //�ô������û��Ϊ��Ӧ���㷨���ó�ʼ������

// 01/03/09�����뿨Ȩ�޹��������
public static long SWR_CARD_MANAGEMENT_DENY =(SWR_CARD_BASE + 0x00001001); //����Ȩ�޲�����
public static long SWR_CARD_OPERATION_DENY =(SWR_CARD_BASE + 0x00001002);//����Ȩ�޲�����
public static long SWR_CARD_DEVICE_STATUS_ERR =(SWR_CARD_BASE + 0x00001003); //��ǰ�豸״̬���������в���
public static long SWR_CARD_LOGIN_ERR =(SWR_CARD_BASE + 0x00001011); //��¼ʧ��
public static long SWR_CARD_USERID_ERR =(SWR_CARD_BASE + 0x00001012); //�û�ID��Ŀ/�������
public static long SWR_CARD_PARAMENT_ERR =(SWR_CARD_BASE + 0x00001013); //��������

// 05/06�����뿨Ȩ�޹��������
public static long SWR_CARD_MANAGEMENT_DENY_05 = (SWR_CARD_BASE + 0x00000801); //����Ȩ�޲�����
public static long SWR_CARD_OPERATION_DENY_05 =(SWR_CARD_BASE + 0x00000802); //����Ȩ�޲�����
public static long SWR_CARD_DEVICE_STATUS_ERR_05 = (SWR_CARD_BASE + 0x00000803); //��ǰ�豸״̬���������в���
public static long SWR_CARD_LOGIN_ERR_05 =(SWR_CARD_BASE + 0x00000811); //��¼ʧ��
public static long SWR_CARD_USERID_ERR_05 = (SWR_CARD_BASE + 0x00000812); //�û�ID��Ŀ/�������
public static long SWR_CARD_PARAMENT_ERR_05 =(SWR_CARD_BASE + 0x00000813); //��������

/*============================================================*/
/*����������*/
public static long SWR_CARD_READER_BASE =(SDR_BASE + 0x00030000); //	���������ʹ���
public static long SWR_CARD_READER_PIN_ERROR= (SWR_CARD_READER_BASE + 0x000063CE); //�������
public static long SWR_CARD_READER_NO_CARD =(SWR_CARD_READER_BASE + 0x0000FF01); //	ICδ����
public static long SWR_CARD_READER_CARD_INSERT = (SWR_CARD_READER_BASE + 0x0000FF02); //	IC���뷽�����򲻵�λ
public static long SWR_CARD_READER_CARD_INSERT_TYPE =(SWR_CARD_READER_BASE + 0x0000FF03); //	IC���ʹ���

}
