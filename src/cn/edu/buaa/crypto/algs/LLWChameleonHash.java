package cn.edu.buaa.crypto.algs;

import org.bouncycastle.util.encoders.Hex;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.test.FuncTest;

public class LLWChameleonHash extends ChameleonHash implements FuncTest {
	public LLWChameleonHash(Pairing pairing){
		super(pairing);
	}
	
	public Element hashAttribute(Element g, Element h, HashData hd){
		byte[] hashAttribute = super.hash(g, h, hd).toBytes();
		hashAttribute[0] &= 0xEF;
		return this.pairing.getZr().newElementFromBytes(hashAttribute);
	}
	
	public Element hashVerification(Element g, Element h, HashData hd){
		byte[] hashVerify = super.hash(g, h, hd).toBytes();
		hashVerify[0] |= 0x80;
		return this.pairing.getZr().newElementFromBytes(hashVerify);
	}
	
	@Override
	public void FunctionTest() {
		Pairing pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
		
		LLWChameleonHash chameleonHash = new LLWChameleonHash(pairing);
		Keys keys = chameleonHash.keyGen();
		//Test Hash Attribute for a String
		String message1 = "Message1";
		HashData hashData1 = chameleonHash.setHashData(message1.getBytes());
		Element hashedValue1 = chameleonHash.hashAttribute(keys.getG(), keys.getH(), hashData1);
		System.out.println("Message1: r = " + hashData1.getR());
		System.out.println("HashedValue1 = " + Hex.toHexString(hashedValue1.toBytes()));
		
		//Forge
		String message2 = "Message2";
		HashData hashData2 = chameleonHash.uforge(keys.getPrivateKey(), hashData1, message2.getBytes());
		Element hashedValue2 = chameleonHash.hashAttribute(keys.getG(), keys.getH(), hashData2);
		System.out.println("Message2: r = " + hashData2.getR());
		System.out.println("HashedValue2 = " + Hex.toHexString(hashedValue2.toBytes()));
		assert(!hashData1.getR().equals(hashData2.getR()));
		assert(hashedValue1.equals(hashedValue2));
		
		//Test Hash Verification for a String
		Element hashedValue3 = chameleonHash.hashVerification(keys.getG(), keys.getH(), hashData1);
		System.out.println("Message1: r = " + hashData1.getR());
		System.out.println("HashedValue4 = " + Hex.toHexString(hashedValue3.toBytes()));
		
		//Forge
		Element hashedValue4 = chameleonHash.hashVerification(keys.getG(), keys.getH(), hashData2);
		System.out.println("Message2: r = " + hashData2.getR());
		System.out.println("HashedValue4 = " + Hex.toHexString(hashedValue4.toBytes()));
		assert(!hashData1.getR().equals(hashData2.getR()));
		assert(hashedValue1.equals(hashedValue2));
	}
}
