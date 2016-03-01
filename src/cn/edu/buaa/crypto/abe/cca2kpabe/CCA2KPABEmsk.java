package cn.edu.buaa.crypto.abe.cca2kpabe;

import it.unisa.dia.gas.jpbc.Element;

public class CCA2KPABEmsk {
	private final Element alpha;
	
	public CCA2KPABEmsk(Element alpha){
		this.alpha = alpha.duplicate().getImmutable();
	}
	
	public Element alpha(){
		return this.alpha;
	}
}