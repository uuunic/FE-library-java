package cn.edu.buaa.crypto.hibbe.fullcpa;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class HIBBEmsk {
	private Element g_alpha;
	
	public HIBBEmsk(HIBBEpp pp, Element alpha){
		this.g_alpha = pp.get_g().powZn(alpha).getImmutable();	
	}
	
	public Element get_g_alpha(){
		return this.g_alpha.duplicate();
	}
}
