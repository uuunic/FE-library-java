package cn.edu.buaa.crypto.abe.cca2cpabe;

import it.unisa.dia.gas.jpbc.Element;

public class CCA2CPABEmsk {
	private final Element alpha;
	
	public CCA2CPABEmsk(Element alpha){
		this.alpha = alpha.duplicate().getImmutable();
	}
	
	public Element alpha(){
		return this.alpha;
	}
}