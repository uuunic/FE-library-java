/*
* Wu Q, Mu Y, Susilo W, et al. Asymmetric group key agreement[M]
* Advances in Cryptology-EUROCRYPT 2009. Springer Berlin Heidelberg, 2009: 153-170.
*
* */
package cn.edu.buaa.crypto.library.asgka;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.util.StdOut;

public class ASGKA {
	private ASGKAGroupParameter param;
	
	public ASGKA(int n){
		StdOut.println("Group Setup");
		Pairing pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
		this.param = new ASGKAGroupParameter(pairing, n);
	}
	
	public ASGKAGroupKey groupKeyAgreement(int i){
		StdOut.println("Group Key Agreement for User " + i);
		Element X_i = param.pairing().getG1().newRandomElement().getImmutable();
		Element r_i = param.pairing().getZr().newRandomElement().getImmutable();
		
		this.param.setSigma(i, X_i.duplicate(), r_i.duplicate());
		ASGKAGroupKey groupKey = new ASGKAGroupKey(param, i, X_i.duplicate(), r_i.duplicate());
		StdOut.println("[Group Key Agreement] Group Key for User " + i + " = " + groupKey.sigma_i_i());
		return groupKey;
	}
	
	public ASGKAGroupEncryptionKey groupEncryptionKeyDerivation(){
		StdOut.println("Group Encryption Key Derivation");
		ASGKAGroupEncryptionKey encryptionKey = new ASGKAGroupEncryptionKey(param);
		StdOut.println("[Group Encryption Key Derivation] R = " + encryptionKey.R());
		StdOut.println("[Group Encryption Key Derivation] A = " + encryptionKey.A());
		return encryptionKey;
	}
	
	public ASGKACiphertext encryption(ASGKAGroupEncryptionKey key, Element m){
		StdOut.println("Encryption");
		ASGKACiphertext ciphertext =  new ASGKACiphertext(param, key, m);
		StdOut.println("[ASGKACiphertext] The encrypted message = " + m);
		return ciphertext;
	}
	
	public Element decryption(ASGKAGroupKey key, ASGKACiphertext ciphertext){
		StdOut.println("Decryption for User " + key.i());
		Element sigma_i = key.sigma_i_i();
		for (int j=0; j<param.n(); j++){
			if (j == key.i()){
				continue;
			} else {
				sigma_i = sigma_i.mul(param.sigma_i_j(j, key.i()));
			}
		}
		Element temp1 = param.pairing().pairing(sigma_i, ciphertext.c_1()).getImmutable();
		temp1 = temp1.mul(param.pairing().pairing(param.array_h(key.i()), ciphertext.c_2())).invert();
		Element m = temp1.mul(ciphertext.c_3()).getImmutable();
		StdOut.println("[decryption] the decrypted massage = " + m);
		return m;
	}
	
	public Pairing pairing(){
		return param.pairing();
	}
}
