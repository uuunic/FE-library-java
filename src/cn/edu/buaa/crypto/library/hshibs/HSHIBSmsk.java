package cn.edu.buaa.crypto.library.hshibs;

import it.unisa.dia.gas.jpbc.Element;

public class HSHIBSmsk {
	private final Element d_0;
	private final Element u_0;
	private final Element v_0;
	
	public HSHIBSmsk(HSHIBSpp pp){
		this.d_0 = pp.getPairing().getZr().newRandomElement().getImmutable();
		this.u_0 = pp.getPairing().getG1().newOneElement().getImmutable();
		this.v_0 = pp.get_g().powZn(this.d_0).getImmutable();
	}
	
	public Element get_d_0(){
		return this.d_0.duplicate();
	}
	
	public Element get_u_0(){
		return this.u_0.duplicate();
	}
	
	public Element get_v_0(){
		return this.v_0.duplicate();
	}
}
