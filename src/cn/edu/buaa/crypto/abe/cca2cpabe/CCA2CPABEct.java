package cn.edu.buaa.crypto.abe.cca2cpabe;

import cn.edu.buaa.crypto.abe.Type;
import cn.edu.buaa.crypto.algs.ChameleonHash.HashData;
import cn.edu.buaa.crypto.util.StdOut;
import it.unisa.dia.gas.jpbc.Element;

public class CCA2CPABEct {
	private Element rChameleonHash;
	
	public Element rChameleonHash(){
		return this.rChameleonHash.duplicate();
	}
	
	private Element C_0;
	
	//For validity Verification
	private Element C_0_1;
	
	public Element C_0_1(){
		return this.C_0_1.duplicate();
	}
	
	private Element C_0_2;
	
	public Element C_0_2(){
		return this.C_0_2.duplicate();
	}
	
	private Element C_0_3;
	
	public Element C_0_3(){
		return this.C_0_3.duplicate();
	}
	
	private transient Element key;
	private transient Element s;
	
	private final CCA2CPABEPolicyNode rootNode;
	
	public CCA2CPABEct(CCA2CPABEpp pp, String policy){	
		this.s = pp.getPairing().getZr().newRandomElement().getImmutable();
		this.rootNode = CCA2CPABEPolicyNode.parsePolicy(pp.getPairing(), policy);
		CCA2CPABEPolicyNode.sharePolicy(pp, rootNode, s);
	}
	
	public void Encrypt(CCA2CPABEpp pp){
		this.C_0 = pp.g().powZn(s.duplicate()).getImmutable();
		CCA2CPABEPolicyNode.fillPolicy(pp, this.rootNode);
		
		this.key = pp.hat_alpha().powZn(s.duplicate()).getImmutable();
		StdOut.println("LLWCPABE Encrypt: Encapsulated Key = " + key);
		
		if (pp.getType() == Type.CCA2){
			//Calculate Verification Attribute
			HashData hashData = pp.getChameleonHash().setHashData(CCA2CPABEPolicyNode.getVerifyAttribute(this.rootNode));
			Element verificationAttribute = pp.getChameleonHash().hashVerification(pp.get_gChameleonHash(), pp.get_hChameleonHash(), hashData).getImmutable();
			this.rChameleonHash = hashData.getR().duplicate().getImmutable();
			//Calculate Verification Component
			Element t_0 = pp.getPairing().getZr().newRandomElement().getImmutable();
			this.C_0_1 = pp.w().powZn(s.duplicate()).mul(pp.v().powZn(t_0.duplicate())).getImmutable();
			this.C_0_2 = pp.u().powZn(verificationAttribute).mul(pp.h()).invert().powZn(t_0.duplicate()).getImmutable();
			this.C_0_3 = pp.g().powZn(t_0.duplicate()).getImmutable();
		}
	}
	
	public Element C_0(){
		return this.C_0.duplicate();
	}
	
	public Element key(){
		return this.key.duplicate();
	}
	
	public CCA2CPABEPolicyNode getPolicyTree(){
		return this.rootNode;
	}
}
