package other;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import com.No_N_Name.jce.provider.No_NameProvider;

import com.No_N_Name.jce.provider.utils.BytesUtil;

public class a {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		//����������в���
		No_NameProvider provider = new No_NameProvider();
		Security.addProvider(provider);
		SecureRandom secureRandom = SecureRandom.getInstance("RND",provider);
		
		byte[] seed = secureRandom.generateSeed(18);
		secureRandom.setSeed(seed);
		
		byte[] random = new byte[18];
		secureRandom.nextBytes(random);
		System.out.println(BytesUtil.bytes2int(random));
		
	}

}
