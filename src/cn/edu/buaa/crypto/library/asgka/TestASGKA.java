package cn.edu.buaa.crypto.library.asgka;

import it.unisa.dia.gas.jpbc.Element;

public class TestASGKA {
	public static void main(String[] args){
		int n = 10;
		ASGKA insASGKA = new ASGKA(n);
		ASGKAGroupKey[] groupKey = new ASGKAGroupKey[n];
		for (int i=0; i<groupKey.length; i++){
			groupKey[i] = insASGKA.groupKeyAgreement(i);
		}
		
		ASGKAGroupEncryptionKey encryptionKey = insASGKA.groupEncryptionKeyDerivation();
		
		Element message = insASGKA.pairing().getGT().newRandomElement().getImmutable();
		ASGKACiphertext ciphertext = insASGKA.encryption(encryptionKey, message);
		
		for (int i=0; i<groupKey.length; i++){
			insASGKA.decryption(groupKey[i], ciphertext);
		}
	}
}
