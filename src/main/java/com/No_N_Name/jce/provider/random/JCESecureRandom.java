package com.No_N_Name.jce.provider.random;

import java.security.SecureRandomSpi;

import com.No_N_Name.jce.Info.Device_Info;
import com.No_N_Name.jce.jna.SDFInterface;
import com.sun.jna.ptr.PointerByReference;
import com.sun.org.apache.bcel.internal.util.ByteSequence;

public class JCESecureRandom extends SecureRandomSpi{
	private byte[] seed;
	@Override
	protected void engineSetSeed(byte[] seed) {
		System.out.println("未装载seed算法");
		
	}
	@Override
	protected void engineNextBytes(byte[] bytes) {
		//把bytes装入并返回
		int result = 1;
		//打开Device
		result = SDFInterface.instanseLib.sdf_set_config_file("device_type=rpc\nrpc_host=192.168.1.108\nrpc_port=5000");
		System.out.println("修改config"+result);
		PointerByReference open_pointer = new PointerByReference();
		open_pointer = Device_Info.getSingleton().getDevice_pointer();
		result = SDFInterface.instanseLib.SDF_OpenDevice(open_pointer);
		Device_Info.getSingleton().setDevice_pointer(open_pointer);
		System.out.println("打开device"+result);
		//打开session
		PointerByReference session_id_p = new PointerByReference();	//存放session
		result = SDFInterface.instanseLib.SDF_OpenSession(Device_Info.getSingleton().getDevice_pointer().getValue(), session_id_p);
		System.out.println("打开session"+result);
		
		result = SDFInterface.instanseLib.SDF_GenerateRandom(session_id_p.getValue(), bytes.length, bytes);
		
		result = SDFInterface.instanseLib.SDF_CloseSession(session_id_p.getValue());
		System.out.println("关闭session"+result);
		result = SDFInterface.instanseLib.SDF_CloseDevice(Device_Info.getSingleton().getDevice_pointer().getValue());
		System.out.println("关闭device"+result);
	}
	@Override
	protected byte[] engineGenerateSeed(int numBytes) {
		return null;
	}
	
}
