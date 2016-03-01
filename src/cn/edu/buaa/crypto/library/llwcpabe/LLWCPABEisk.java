package cn.edu.buaa.crypto.library.llwcpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class LLWCPABEisk {
	private final Element K_0;
	private final Element K_1;
	private final LLWCPABEiskComps[] iskComps;
	private final int P;
	
	public class LLWCPABEiskComps{
		//private final Pairing pairing;
		
		//elements for that component, K_2, K_3
		private final Element K_2;
		private final Element K_3;
		private final Element x_i;
		private final Element r_i;

		public LLWCPABEiskComps(Pairing pairing, LLWCPABEpp pp, Element r){
			this.r_i = pairing.getZr().newRandomElement().getImmutable();
			this.K_2 = pp.g().powZn(r_i).getImmutable();
			this.x_i = pairing.getZr().newRandomElement().getImmutable();
			this.K_3 = pp.u().powZn(x_i).mul(pp.h()).powZn(r_i).mul(pp.v().invert().powZn(r.duplicate())).getImmutable();
		}
		
		public Element K_2(){
			return this.K_2.duplicate();
		}
		
		public Element K_3(){
			return this.K_3.duplicate();
		}
		
		public Element x_i(){
			return this.x_i.duplicate();
		}
		
		public Element r_i(){
			return this.r_i.duplicate();
		}
	}
	
	public LLWCPABEisk(Pairing pairing, LLWCPABEpp pp, LLWCPABEmsk msk, int P){
		this.P = P;
		Element r = pairing.getZr().newRandomElement().getImmutable();
		this.K_0 = pp.g().powZn(msk.alpha()).mul(pp.w().powZn(r)).getImmutable();
		this.K_1 = pp.g().powZn(r).getImmutable();
		
		this.iskComps = new LLWCPABEiskComps[P];
		for (int i=0; i<iskComps.length; i++){
			iskComps[i] = new LLWCPABEiskComps(pairing, pp, r);
		}
	}
	
	public int P(){
		return this.P;
	}
	
	public Element K_0(){
		return this.K_0.duplicate();
	}
	
	public Element K_1(){
		return this.K_1.duplicate();
	}
	
	public LLWCPABEiskComps iskComps(int index){
		assert (index < this.P);
		return this.iskComps[index];
	}
}
