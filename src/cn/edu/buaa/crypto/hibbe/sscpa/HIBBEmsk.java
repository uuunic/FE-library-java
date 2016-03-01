package cn.edu.buaa.crypto.hibbe.sscpa;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class HIBBEmsk {
	private Element g_2_alpha;
	
	public HIBBEmsk(HIBBEpp pp, Element alpha){
		this.g_2_alpha = pp.get_g_2().powZn(alpha).getImmutable();	
	}
	
	public Element get_g_2_alpha(){
		return this.g_2_alpha.duplicate();
	}
}
