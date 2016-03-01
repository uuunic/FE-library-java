package cn.edu.buaa.crypto.library.asgka;

import it.unisa.dia.gas.jpbc.Element;

public class ASGKAGroupKey {
	private final int i;
	private final Element sigma_i_i;
	
	public ASGKAGroupKey(ASGKAGroupParameter param, final int i, Element X_i, Element r_i){
		this.i = i;
		this.sigma_i_i = X_i.duplicate().mul(param.array_h(i).powZn(r_i.duplicate())).getImmutable();
	}
	
	public int i(){
		return this.i;
	}
	
	public Element sigma_i_i(){
		return this.sigma_i_i.duplicate();
	}
}
