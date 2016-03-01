package cn.edu.buaa.crypto.library.llwrbac;

import it.unisa.dia.gas.jpbc.Element;

public class LLWRBACiac {
	private final Element g;
	private final Element g_3;
	private final Element[] u;
	
	public LLWRBACiac(LLWRBACpp pp){
		this.u = new Element[pp.get_u_length()];
		Element r = pp.get_pairing().getZr().newRandomElement().getImmutable();
		for (int i=0; i<pp.get_u_length(); i++){
			this.u[i] = pp.get_u(i).powZn(r).getImmutable();
		}
		this.g = pp.get_g().duplicate().powZn(r).getImmutable();
		this.g_3 = pp.get_g_3().duplicate().powZn(r).getImmutable();
	}
	
	public Element get_g(){
		return this.g.duplicate();
	}
	
	public Element get_g_3(){
		return this.g_3.duplicate();
	}
	
	public Element get_u(int index){
		return this.u[index].duplicate();
	}
}
