package cn.edu.buaa.crypto.library.llwcpabe;

import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.algs.LLWChameleonHash;
import cn.edu.buaa.crypto.util.StdOut;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class LLWCPABEict {
	//private Pairing pairing;
	private final int P;
	private final Element key;
	
	public Element key(){
		return this.key.duplicate();
	}
	
	private final Element s;
	
	public Element s(){
		return this.s.duplicate();
	}
	
	private final Element gChameleonHash;
	
	public Element gChameleonHash(){
		return this.gChameleonHash.duplicate();
	}
	
	private final Element hChameleonHash;
	
	public Element hChameleonHash(){
		return this.hChameleonHash.duplicate();
	}
	
	private final Element skChameleonHash;
	
	public Element skChameleonHash(){
		return this.skChameleonHash.duplicate();
	}
	
	private final Element r_p;
	
	public Element r_p(){
		return this.r_p.duplicate();
	}
	
	private final Element V_p;
	
	public Element V_p(){
		return this.V_p.duplicate();
	}
	
	private final Element C_0;
	
	public Element C_0(){
		return this.C_0.duplicate();
	}
	
	private final Element C_0_1;
	
	public Element C_0_1(){
		return this.C_0_1.duplicate();
	}
	
	private final Element C_0_2;
	
	public Element C_0_2(){
		return this.C_0_2.duplicate();
	}
	
	private final Element C_0_3;
	
	public Element C_0_3(){
		return this.C_0_3.duplicate();
	}
	
	private final Element[] lambda_i;
	private final Element[] x_i;
	private final Element[] t_i;
	private final Element[] C_i_1;
	private final Element[] C_i_2;
	private final Element[] C_i_3;
	
	private int current;
	
	public Element[] ictComps_i(){
		assert(current < P);
		Element[] result = new Element[6];
		result[0] = this.lambda_i[current].duplicate();
		result[1] = this.x_i[current].duplicate();
		result[2] = this.t_i[current].duplicate();
		result[3] = this.C_i_1[current].duplicate();
		result[4] = this.C_i_2[current].duplicate();
		result[5] = this.C_i_3[current].duplicate();
		current++;
		return result;
	}
	
	public LLWCPABEict(Pairing pairing, LLWCPABEpp pp, int P){
		this.current = 0;
		this.P = P;
		this.s = pairing.getZr().newRandomElement().getImmutable();
		this.C_0 = pp.g().powZn(this.s.duplicate()).getImmutable();
		this.key = pp.hat_alpha().powZn(s.duplicate()).getImmutable();
		
		LLWChameleonHash chameleonHash = new LLWChameleonHash(pairing);
		LLWChameleonHash.Keys keys = chameleonHash.keyGen();
		this.gChameleonHash = keys.getG().duplicate().getImmutable();
		this.hChameleonHash = keys.getH().duplicate().getImmutable();
		this.skChameleonHash = keys.getPrivateKey().duplicate().getImmutable();
		
		this.V_p = pairing.getZr().newRandomElement().getImmutable();
		LLWChameleonHash.HashData hashData = chameleonHash.setHashData(V_p.toBytes());
		this.r_p = hashData.getR().duplicate().getImmutable();
		
		Element V_p_hash = chameleonHash.hashVerification(this.gChameleonHash, this.hChameleonHash, hashData);
		Element t_0 = pairing.getZr().newRandomElement().getImmutable();
		this.C_0_1 = pp.w().powZn(s.duplicate()).mul(pp.v().powZn(t_0.duplicate())).getImmutable();
		this.C_0_2 = pp.u().powZn(V_p_hash.duplicate()).mul(pp.h()).invert().powZn(t_0.duplicate()).getImmutable();
		this.C_0_3 = pp.g().powZn(t_0.duplicate()).getImmutable();
		
		this.lambda_i = new Element[this.P];
		this.x_i = new Element[this.P];
		this.t_i = new Element[this.P];
		this.C_i_1 = new Element[this.P];
		this.C_i_2 = new Element[this.P];
		this.C_i_3 = new Element[this.P];
		for (int i=0; i<this.P; i++){
			this.lambda_i[i] = pairing.getZr().newRandomElement().getImmutable();
			this.x_i[i] = pairing.getZr().newRandomElement().getImmutable();
			this.t_i[i] = pairing.getZr().newRandomElement().getImmutable();
			
			this.C_i_1[i] = pp.w().powZn(this.lambda_i[i].duplicate()).mul(pp.v().powZn(this.t_i[i].duplicate())).getImmutable();
			this.C_i_2[i] = pp.u().powZn(this.x_i[i].duplicate()).mul(pp.h()).invert().powZn(this.t_i[i].duplicate()).getImmutable();
			this.C_i_3[i] = pp.g().powZn(this.t_i[i].duplicate()).getImmutable();
		}
	}
}
