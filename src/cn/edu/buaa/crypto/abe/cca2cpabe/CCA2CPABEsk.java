package cn.edu.buaa.crypto.abe.cca2cpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import cn.edu.buaa.crypto.algs.GroupHash;

public class CCA2CPABEsk {
//	private final Pairing pairing;
	private final Element K_0;
	private final Element K_1;
	private final CCA2CPABEskComps[] skComps;
	private final int numOfAttrs;
	
	public CCA2CPABEsk(CCA2CPABEpp pp, CCA2CPABEmsk msk, String[] attrs){
		Element r = pp.getPairing().getZr().newRandomElement().getImmutable();
		this.K_0 = pp.g().powZn(msk.alpha()).mul(pp.w().powZn(r)).getImmutable();
		this.K_1 = pp.g().powZn(r).getImmutable();
		this.numOfAttrs = attrs.length;
		skComps = new CCA2CPABEskComps[numOfAttrs];
		
		for (int i=0; i<numOfAttrs; i++){
			skComps[i] = new CCA2CPABEskComps(pp.getPairing(), pp, attrs[i], r);
		}
	}
	
	public Element K_0(){
		return this.K_0.duplicate();
	}
	
	public Element K_1(){
		return this.K_1.duplicate();
	}
	
	public int numOfAttrs(){
		return this.numOfAttrs;
	}
	
	public CCA2CPABEskComps skComps(int index){
		assert(index < this.numOfAttrs);
		return this.skComps[index];
	}
	
	public class CCA2CPABEskComps{
//		private final Pairing pairing;
		//attribute for that component
		private final String attribute;
		private final Element A_i;
		//elements for that component, K_2, K_3, K_4
		private final Element K_2;
		private final Element K_3;
		
		public CCA2CPABEskComps(Pairing pairing, CCA2CPABEpp pp, String attribute, Element r){
			this.attribute = attribute;
			Element r_i = pairing.getZr().newRandomElement().getImmutable();
			this.K_2 = pp.g().powZn(r_i.duplicate()).getImmutable();
			this.A_i = GroupHash.HashToZp(pairing, attribute.getBytes()).getImmutable();
			this.K_3 = pp.u().powZn(A_i).mul(pp.h()).powZn(r_i.duplicate()).mul(pp.v().invert().powZn(r.duplicate())).getImmutable();
		}
		
		public String attribute(){
			return this.attribute;
		}
		
		public Element K_2(){
			return this.K_2.duplicate();
		}
		
		public Element K_3(){
			return this.K_3.duplicate();
		}
		
		public Element A(){
			return this.A_i.duplicate();
		}
	}
}
