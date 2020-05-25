package com.No_N_Name.jce.provider;
import java.security.AccessController;
import java.security.AuthProvider;
import java.security.PrivilegedAction;
import java.security.SecurityPermission;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

public class No_NameProvider extends AuthProvider {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static String name = "No_NameProvider";
	private static String info = "�������Provider��û������";
	private static double version = 1.0d;
	
	public No_NameProvider() {
		super(name,version,info);
		//��jce��Ȩ
		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			@Override
			public Object run() {
                                //�����Լ��Ļ���ʵ����
                                //��ʽ������.�㷨
				
				put("SecureRandom.RND" , "com.No_N_Name.jce.provider.random.JCESecureRandom");
				put("KeyPairGenerator.RSA" , "com.No_N_Name.jce.provider.RSA.RSAKeyPairGeneratorSpi");
				put("Cipher.RSA" , "com.No_N_Name.jce.provider.RSA.RSACipherSpi");

				return null;
			}
 
		});
	}
	protected No_NameProvider(String name, double version, String info) {
		super(name, version, info);
	}

	@Override
	public void login(Subject subject, CallbackHandler handler) throws LoginException {
		SecurityManager sManager = System.getSecurityManager();
		sManager.checkPermission(new SecurityPermission("authProvider."+ this.getName()));
	}

	@Override
	public void logout() throws LoginException {
		
	}

	@Override
	public void setCallbackHandler(CallbackHandler handler) {
		
	}
	
	//��ȡ���ֵ�
	public String getName() {
		return name;
	}
 
	public String getInfo() {
		return info;
	}
 
	public double getVersion() {
		return version;
	}
}
