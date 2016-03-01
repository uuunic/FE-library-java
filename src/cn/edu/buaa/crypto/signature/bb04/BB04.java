package cn.edu.buaa.crypto.signature.bb04;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class BB04 {
	public static BB04sk KeyGenSK(Pairing pairing){
		return new BB04sk(pairing);
	}
	
	public static BB04vk KeyGenVK(Pairing pairing, BB04sk sk){
		return new BB04vk(pairing, sk);
	}
	
	public static BB04sign Signing(Pairing pairing, BB04sk sk, byte[] message){
		return new BB04sign(pairing, sk, message);
	}
	
	public static boolean Verification(Pairing pairing, BB04vk vk, BB04sign sign){
		Element temp1 = vk.get_u().mul(vk.get_g_2().powZn(sign.get_hash_message())).mul(vk.get_v().powZn(sign.get_r()));
		Element pairing1 = pairing.pairing(sign.get_sigma(), temp1);
		Element pairing2 = vk.get_z();
		return (pairing1.equals(pairing2));
	}
}
