package cn.edu.buaa.crypto.library.llwcpabe;

import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.library.llwcpabe.LLWCPABEisk.LLWCPABEiskComps;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;


public class LLWCPABEsk {	
//	private final Pairing pairing;
	private final Element K_0;
	private final Element K_1;
	private final LLWCPABEskComps[] skComps;
	private final int numOfAttrs;
	
	public LLWCPABEsk(Pairing pairing, LLWCPABEpp pp, LLWCPABEmsk msk, String[] attrs){
		Element r = pairing.getZr().newRandomElement().getImmutable();
		this.K_0 = pp.g().powZn(msk.alpha()).mul(pp.w().powZn(r)).getImmutable();
		this.K_1 = pp.g().powZn(r).getImmutable();
		this.numOfAttrs = attrs.length;
		skComps = new LLWCPABEskComps[numOfAttrs];
		
		for (int i=0; i<numOfAttrs; i++){
			skComps[i] = new LLWCPABEskComps(pairing, pp, attrs[i], r);
		}
	}
	
	public LLWCPABEsk(Pairing pairing, LLWCPABEpp pp, String[] attrs, LLWCPABEisk isk){
		this.K_0 = isk.K_0().duplicate().getImmutable();
		this.K_1 = isk.K_1().duplicate().getImmutable();
		this.numOfAttrs = attrs.length;
		assert (numOfAttrs <= isk.P());
		
		skComps = new LLWCPABEskComps[numOfAttrs];
		for (int i=0; i<numOfAttrs; i++){
			skComps[i] = new LLWCPABEskComps(pairing, pp, attrs[i], isk.iskComps(i));
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
	
	public LLWCPABEskComps skComps(int index){
		assert(index < this.numOfAttrs);
		return this.skComps[index];
	}
	
	public class LLWCPABEskComps{
//		private final Pairing pairing;
		//attribute for that component
		private final String attribute;
		private final Element A_i;
		//elements for that component, K_2, K_3, K_4
		private final Element K_2;
		private final Element K_3;
		private final Element K_4;
		
		public LLWCPABEskComps(Pairing pairing, LLWCPABEpp pp, String attribute, Element r){
			this.attribute = attribute;
			Element r_i = pairing.getZr().newRandomElement().getImmutable();
			this.K_2 = pp.g().powZn(r_i.duplicate()).getImmutable();
			this.A_i = GroupHash.HashToZp(pairing, attribute.getBytes()).getImmutable();
			this.K_3 = pp.u().powZn(A_i).mul(pp.h()).powZn(r_i.duplicate()).mul(pp.v().invert().powZn(r.duplicate())).getImmutable();
			this.K_4 = pairing.getZr().newZeroElement().getImmutable();
		}
		
		public LLWCPABEskComps(Pairing pairing, LLWCPABEpp pp, String attribute, LLWCPABEiskComps iskComps){
			this.attribute = attribute;
			this.K_2 = iskComps.K_2().duplicate().getImmutable();
			this.K_3 = iskComps.K_3().duplicate().getImmutable();
			this.A_i = GroupHash.HashToZp(pairing, attribute.getBytes()).getImmutable();
			this.K_4 = A_i.sub(iskComps.x_i()).mul(iskComps.r_i()).getImmutable();
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
		
		public Element K_4(){
			return this.K_4.duplicate();
		}
		
		public Element A(){
			return this.A_i.duplicate();
		}
	}
}
