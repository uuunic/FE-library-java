package cn.edu.buaa.crypto.signature.bb04;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.util.StdOut;

public class TestBB04 {
	public static void main(String[] args){
		Pairing pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);
		BB04sk sk = BB04.KeyGenSK(pairing);
		BB04vk vk = BB04.KeyGenVK(pairing, sk);
		
		byte[] message = new String("Test Message").getBytes();
		BB04sign sign = BB04.Signing(pairing, sk, message);
		StdOut.println(BB04.Verification(pairing, vk, sign));
	}
}
