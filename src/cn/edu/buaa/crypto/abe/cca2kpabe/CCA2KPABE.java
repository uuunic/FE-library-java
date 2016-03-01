package cn.edu.buaa.crypto.abe.cca2kpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cn.edu.buaa.crypto.abe.Type;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.util.StdOut;

public class CCA2KPABE {
	private final Pairing pairing;
	private CCA2KPABEpp pp;
	
	/**
	 * Construct an instance of CCA2-secure CPABE scheme
	 */
	public CCA2KPABE(){
		this.pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
	}
	
	/**
	 * Obtain the public parameter from the CCA2-secure CAPBE instance
	 * @return public parameter pp
	 */
	public CCA2KPABEpp getPublicParameter(){
		return this.pp;
	}
	
	/**
	 * Setup algorithm, setting up the LLWCPABE scheme
	 * @return master secret key msk
	 */
	public CCA2KPABEmsk Setup(Type type){
		StdOut.println("Setup: System Setup.");
		Element alpha = pairing.getZr().newRandomElement().getImmutable();
		CCA2KPABEmsk msk = new CCA2KPABEmsk(alpha);
		this.pp = new CCA2KPABEpp(pairing, type, alpha);
		return msk;
	}
	
	public CCA2KPABEsk KeyGen_LSSS(CCA2KPABEpp pp, CCA2KPABEmsk msk, String policy){
		StdOut.println("KeyGen: Linear Secret Sharing Scheme");
		CCA2KPABEsk sk = new CCA2KPABEsk(pp, msk, policy);
		return sk;
	}
	
	/**
	 * KeyGen Algorithm
	 * @param pp public parameter
	 * @param msk master secret key
	 * @param policy access policy
	 */
	public void KeyGen(CCA2KPABEpp pp, CCA2KPABEmsk msk, CCA2KPABEsk sk){
		sk.KeyGen(pp, msk);
	}
	
	/**
	 * Encryption Algorithm
	 * @param pp public parameter
	 * @param attrs attribute set for the key
	 * @return ciphertext associated with attribute set
	 */
	public CCA2KPABEct Encrypt(CCA2KPABEpp pp, String[] attrs){
		String combinedAttrs = new String("");
		for (String attr: attrs){
			combinedAttrs = combinedAttrs.concat(attr + " ");
		}
		StdOut.println("Encrypt: Generate ciphertext with attributes = " + combinedAttrs);
		return new CCA2KPABEct(pp, attrs);
	}
	
	/**
	 * Audit Algorithm
	 * @param pp public parameter
	 * @param ct ciphertex to be audited
	 * @return true if valid, false if invalid
	 */
	private boolean Audit(CCA2KPABEpp pp, CCA2KPABEct ct){
		return CCA2KPABEct.Audit(pp, ct);
	}
	
	/**
	 * Decrypt Algorithm for recovering data byte[]
	 * @param pp public parameter
	 * @param sk secret key
	 * @param ct ciphetext
	 * @return encapsuated key
	 */
	public Element Decrypt(CCA2KPABEpp pp, CCA2KPABEsk sk, CCA2KPABEct ct){
		if(!this.Audit(pp, ct)){
			return null;
		}
		
		Element key = CCA2KPABEPolicyNode.decrypt(pp, ct, sk.getPolicyTree());
		if (key == null){
			StdOut.println("Do not satisfy the access policy, decrypt fail...");
			return null;
		}
		StdOut.println("LLWCPABE Decrypt: Encapsulated key = " + key);
		return key;
	}
}

	