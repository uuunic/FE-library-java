package cn.edu.buaa.crypto.library.llwcpabe;

import it.unisa.dia.gas.jpbc.Element;

public class LLWCPABEmsk {
	private final Element alpha;
	
	public LLWCPABEmsk(Element alpha){
		this.alpha = alpha.duplicate().getImmutable();
	}
	
	public Element alpha(){
		return this.alpha;
	}
}
