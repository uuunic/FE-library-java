package cn.edu.buaa.crypto.library.llwcpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import cn.edu.buaa.crypto.library.llwcpabe.LLWCPABEsk.LLWCPABEskComps;

public class LLWCPABEtk {
//	private final Pairing pairing;
	private final Element K_0;
	private final Element K_1;
	private final LLWCPABEtkComps[] tkComps;
	private final int numOfAttrs;
	
	private final Element z;
	
	public LLWCPABEtk(LLWCPABEpp pp, LLWCPABEsk sk){
		this.z = pp.getPairing().getZr().newRandomElement().getImmutable();
		Element z_invert = z.duplicate().invert().getImmutable();
		this.K_0 = sk.K_0().powZn(z_invert.duplicate()).getImmutable();
		this.K_1 = sk.K_1().powZn(z_invert.duplicate()).getImmutable();
		this.numOfAttrs = sk.numOfAttrs();
		this.tkComps = new LLWCPABEtkComps[numOfAttrs];
		
		for (int i=0; i<numOfAttrs; i++){
			tkComps[i] = new LLWCPABEtkComps(sk.skComps(i), z_invert);
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
	
	public LLWCPABEtkComps tkComps(int index){
		assert(index < this.numOfAttrs);
		return this.tkComps[index];
	}
	
	public Element z(){
		return this.z.duplicate();
	}
	
	public class LLWCPABEtkComps{
//		private final Pairing pairing;
		//attribute for that component
		private final String attribute;
		private final Element A_i;
		//elements for that component, K_2, K_3, K_4
		private final Element K_2;
		private final Element K_3;
		private final Element K_4;
		
		public LLWCPABEtkComps(LLWCPABEskComps skComps, Element z_invert){
			this.attribute = skComps.attribute();
			this.K_2 = skComps.K_2().powZn(z_invert.duplicate()).getImmutable();
			this.A_i = skComps.A();
			this.K_3 = skComps.K_3().powZn(z_invert.duplicate()).getImmutable();
			this.K_4 = skComps.K_4().div(z_invert.duplicate()).getImmutable();
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
