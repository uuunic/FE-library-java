/*
* Krawczyk, Hugo, and Tal Rabin. "Chameleon Hashing and Signatures.." IACR Cryptology ePrint Archive 1998 (1998).
* */
package cn.edu.buaa.crypto.algs;

import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.test.FuncTest;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class ChameleonHash implements FuncTest {
	
	//ChameleonHash Key Pairs
	public class Keys {
		private Element privateKey;
		
		private Element[] publicKey;
		
		public Keys(Element privateKey, Element g, Element h){
			this.publicKey = new Element[2];
			
			this.privateKey = privateKey.getImmutable();
			this.publicKey[0] = g.getImmutable();
			this.publicKey[1] = h.getImmutable();
		}
		
		public Element getPrivateKey(){
			return this.privateKey.duplicate();
		}
		
		public Element getH(){
			return this.publicKey[1].duplicate();
		}
		
		public Element getG(){
			return this.publicKey[0].duplicate();
		}
	}
	
	//ChameleonHash Data
	public class HashData {
		private final Element value;
		private final Element r;
		
		private HashData(Element data, Element r){
			this.value = data;
			this.r = r;
		}
		
		public Element getValue(){
			return value.duplicate();
		}
		
		public Element getR(){
			return r.duplicate();
		}
	}
	
	protected final Pairing pairing;

	public ChameleonHash(Pairing pairing){
		this.pairing = pairing;
	}
	
	public Keys keyGen() {
		Element g = pairing.getG1().newRandomElement().getImmutable();
		Element privateKey = pairing.getZr().newRandomElement().getImmutable();
		Element h = g.powZn(privateKey).getImmutable();
		return new Keys(privateKey, g, h);
	}
	
	public HashData setHashData(byte[] message){
		Element value = GroupHash.HashToZp(pairing, message).getImmutable();
		Element r = pairing.getZr().newRandomElement().getImmutable();
		
		return new HashData(value, r);
	}
	
	public HashData setHashData(byte[] message, Element r){
		Element value = GroupHash.HashToZp(pairing, message).getImmutable();
		
		return new HashData(value, r.duplicate().getImmutable());
	}
	
	public Element hash(Element g, Element h, HashData hd){
		byte[] hashed = g.powZn(hd.getValue()).mul(h.powZn(hd.getR())).getImmutable().toBytes();	
		return this.pairing.getZr().newElementFromBytes(hashed);
	}
	
	public HashData uforge(Element sk, HashData hd1, byte[] message){
		Element value = GroupHash.HashToZp(pairing, message).getImmutable();
		Element r_shadow = hd1.getValue().sub(value).mulZn(sk.invert()).add(hd1.getR()).getImmutable();
		
		return setHashData(message, r_shadow);
	}

	@Override
	public void FunctionTest() {
		Pairing pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
		
		LLWChameleonHash chameleonHash = new LLWChameleonHash(pairing);
		Keys keys = chameleonHash.keyGen();
		//Test Hash for a String
		String message1 = "Message1";
		HashData hashData1 = chameleonHash.setHashData(message1.getBytes());
		Element hashedValue1 = chameleonHash.hashVerification(keys.getG(), keys.getH(), hashData1);
		System.out.println("Message1: r = " + hashData1.getR());
		System.out.println("HashedValue1 = " + hashedValue1);
		
		//Forge
		String message2 = "Message2";
		HashData hashData2 = chameleonHash.uforge(keys.getPrivateKey(), hashData1, message2.getBytes());
		Element hashedValue2 = chameleonHash.hashVerification(keys.getG(), keys.getH(), hashData2);
		System.out.println("Message2: r = " + hashData2.getR());
		System.out.println("HashedValue2 = " + hashedValue2);
		assert(!hashData1.getR().equals(hashData2.getR()));
		assert(hashedValue1.equals(hashedValue2));
	}
}
