package cn.edu.buaa.crypto.library.llwcpabe;

import java.io.Serializable;

import cn.edu.buaa.crypto.algs.ChameleonHash;
import cn.edu.buaa.crypto.algs.ChameleonHash.HashData;
import cn.edu.buaa.crypto.algs.GeneralHash;
import cn.edu.buaa.crypto.algs.LLWChameleonHash;
import cn.edu.buaa.crypto.algs.SymmetricBlockEnc;
import cn.edu.buaa.crypto.util.StdOut;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class LLWCPABEct implements Serializable{
//	private final Pairing pairing;
	//pk_{ch}
	private Element gChameleonHash;
	private Element hChameleonHash;
	//r_{ch}
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
	
	private final LLWCPABEPolicyNode rootNode;
	
	public LLWCPABEct(LLWCPABEpp pp, String policy){	
		this.s = pp.getPairing().getZr().newRandomElement().getImmutable();
		this.rootNode = LLWCPABEPolicyNode.parsePolicy(pp.getPairing(), policy);
		LLWCPABEPolicyNode.sharePolicy(pp, rootNode, s);
	}
	
	public void generalEncrypt(LLWCPABEpp pp){
		//generate ChameleonHash keys
		LLWChameleonHash chameleonHash = new LLWChameleonHash(pp.getPairing());
		LLWChameleonHash.Keys keys = chameleonHash.keyGen();
		this.gChameleonHash = keys.getG().duplicate().getImmutable();
		this.hChameleonHash = keys.getH().duplicate().getImmutable();
		
		this.C_0 = pp.g().powZn(s.duplicate()).getImmutable();
		LLWCPABEPolicyNode.fillPolicy(pp, this.rootNode);
		//Calculate Verification Attribute
		HashData hashData = chameleonHash.setHashData(LLWCPABEPolicyNode.getVerifyAttribute(this.rootNode));
		Element verificationAttribute = chameleonHash.hashVerification(this.gChameleonHash, this.hChameleonHash, hashData).getImmutable();
		this.rChameleonHash = hashData.getR().duplicate().getImmutable();
		//Calculate Verification Component
		Element t_0 = pp.getPairing().getZr().newRandomElement().getImmutable();
		this.C_0_1 = pp.w().powZn(s.duplicate()).mul(pp.v().powZn(t_0.duplicate())).getImmutable();
		this.C_0_2 = pp.u().powZn(verificationAttribute).mul(pp.h()).invert().powZn(t_0.duplicate()).getImmutable();
		this.C_0_3 = pp.g().powZn(t_0.duplicate()).getImmutable();
		
		this.key = pp.hat_alpha().powZn(s.duplicate()).getImmutable();
		StdOut.println("LLWCPABE Encrypt: Encapsulated Key = " + key);
	}
	
	public LLWCPABEct(LLWCPABEpp pp, String policy, LLWCPABEict ict){
		this.rootNode = LLWCPABEPolicyNode.parsePolicy(pp.getPairing(), policy);
		LLWCPABEPolicyNode.sharePolicy(pp, rootNode, ict.s());
	}
	
	public void onlineEncrypt(LLWCPABEpp pp, LLWCPABEict ict){
		this.gChameleonHash = ict.gChameleonHash().duplicate().getImmutable();
		this.hChameleonHash = ict.hChameleonHash().duplicate().getImmutable();
		this.C_0 = ict.C_0().duplicate().getImmutable();
		this.C_0_1 = ict.C_0_1().duplicate().getImmutable();
		this.C_0_2 = ict.C_0_2().duplicate().getImmutable();
		this.C_0_3 = ict.C_0_3().duplicate().getImmutable();
		
		this.key = ict.key().duplicate().getImmutable();
		LLWCPABEPolicyNode.fillPolicy(pp, this.rootNode, ict);
		//Calculate Verification Attribute
		LLWChameleonHash chameleonHash = new LLWChameleonHash(pp.getPairing());
		HashData hashData1 = chameleonHash.setHashData(ict.V_p().toBytes(), ict.r_p());
		HashData hashData2 = chameleonHash.uforge(ict.skChameleonHash(), hashData1, LLWCPABEPolicyNode.getVerifyAttribute(this.rootNode));
		
		this.rChameleonHash = hashData2.getR().getImmutable();
		StdOut.println("LLWCPABE Encrypt: Encapsulated Key = " + key);
	}
	
	public Element gChameleonHash(){
		return this.gChameleonHash.duplicate();
	}
	
	public Element hChameleonHash(){
		return this.hChameleonHash.duplicate();
	}
	
	public Element C_0(){
		return this.C_0.duplicate();
	}
	
	public Element key(){
		return this.key.duplicate();
	}
	
	public LLWCPABEPolicyNode getPolicyTree(){
		return this.rootNode;
	}
	
	public long sizeOf(){
		long size = LLWCPABEPolicyNode.sizeOf(rootNode);
		size += this.C_0.toBytes().length;
		size += this.C_0_1.toBytes().length;
		size += this.C_0_2.toBytes().length;
		size += this.C_0_3.toBytes().length;
		size += this.gChameleonHash.toBytes().length;
		size += this.hChameleonHash.toBytes().length;
		size += this.rChameleonHash.toBytes().length;
		return size;
	}
}
