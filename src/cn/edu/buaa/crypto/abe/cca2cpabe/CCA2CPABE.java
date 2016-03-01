package cn.edu.buaa.crypto.abe.cca2cpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import cn.edu.buaa.crypto.abe.Type;
import cn.edu.buaa.crypto.algs.ChameleonHash.HashData;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.util.StdOut;

public class CCA2CPABE {
	private final Pairing pairing;
	private CCA2CPABEpp pp;
	
	/**
	 * Construct an instance of CCA2-secure CPABE scheme
	 */
	public CCA2CPABE(){
		this.pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
	}
	
	/**
	 * Obtain the public parameter from the CCA2-secure CAPBE instance
	 * @return public parameter pp
	 */
	public CCA2CPABEpp getPublicParameter(){
		return this.pp;
	}
	
	/**
	 * Setup algorithm, setting up the LLWCPABE scheme
	 * @return master secret key msk
	 */
	public CCA2CPABEmsk Setup(Type type){
		StdOut.println("Setup: System Setup.");
		Element alpha = pairing.getZr().newRandomElement().getImmutable();
		CCA2CPABEmsk msk = new CCA2CPABEmsk(alpha);
		this.pp = new CCA2CPABEpp(pairing, type, alpha);
		return msk;
	}
	
	/**
	 * General Key Generation Algorithm
	 * @param msk master secret key
	 * @param attrs attribute set for the key
	 * @return secret key associated with attribute set
	 */
	public CCA2CPABEsk KeyGen(CCA2CPABEmsk msk, String[] attrs){
		String combinedAttrs = new String("");
		for (String attr: attrs){
			combinedAttrs = combinedAttrs.concat(attr + " ");
		}
		StdOut.println("General.KeyGen: General Generate secret key with attributes = " + combinedAttrs);
		return new CCA2CPABEsk(pp, msk, attrs);
	}
	
	
	public CCA2CPABEct Encrypt_LSSS(CCA2CPABEpp pp, String policy){
		StdOut.println("General.Encrypt: General Encrypt");
		CCA2CPABEct ct = new CCA2CPABEct(pp, policy);
		return ct;
	}
	
	/**
	 * General Encrypt Algorithm for Encrypting byte[]
	 * @param pp public parameter
	 * @param policy access policy
	 */
	public void Encrypt(CCA2CPABEpp pp, CCA2CPABEct ct){
		ct.Encrypt(pp);
	}
	
	/**
	 * Audit Algorithm
	 * @param pp public parameter
	 * @param ct ciphertex to be audited
	 * @return true if valid, false if invalid
	 */
	private boolean Audit(CCA2CPABEpp pp, CCA2CPABEct ct){
		if (pp.getType() == Type.CPA){
			return true;
		} else {
			HashData hashData = pp.getChameleonHash().setHashData(CCA2CPABEPolicyNode.getVerifyAttribute(ct.getPolicyTree()), ct.rChameleonHash());
			Element verificationAttribute = pp.getChameleonHash().hashVerification(pp.get_gChameleonHash(), pp.get_hChameleonHash(), hashData).getImmutable();
			//Test Verification Attribute
			if (!pairing.pairing(pp.g(), ct.C_0_2()).mul(pairing.pairing(ct.C_0_3(), pp.u().powZn(verificationAttribute).mul(pp.h()))).equals(pairing.getGT().newOneElement())){
				StdOut.println("Audit: Audit Ciphertext result = Invalid...");
				return false;
			} else {
				boolean auditResult = CCA2CPABEPolicyNode.audit(pp, ct.getPolicyTree());
				if (!auditResult){
					StdOut.println("Audit: Audit Ciphertext result = Invalid...");
				} else {
					StdOut.println("Audit: Audit Ciphertext result = Valid!");
				}
				return auditResult;
			}
		}
	}
	
	/**
	 * Decrypt Algorithm for recovering data byte[]
	 * @param pp public parameter
	 * @param sk secret key
	 * @param ct ciphetext
	 * @return encapsuated key
	 */
	public Element Decrypt(CCA2CPABEpp pp, CCA2CPABEsk sk, CCA2CPABEct ct){
		if(!this.Audit(pp, ct)){
			return null;
		}
		Element temp0 = pp.getPairing().pairing(ct.C_0(), sk.K_0()).getImmutable();
		Element temp1 = CCA2CPABEPolicyNode.decrypt(pp, sk, ct.getPolicyTree());
		if (temp1 == null){
			StdOut.println("Do not satisfy the access policy, decrypt fail...");
			return null;
		}
		Element key = temp0.mul(temp1.invert()).getImmutable();
		StdOut.println("LLWCPABE Decrypt: Encapsulated key = " + key);
		return key;
	}
}
