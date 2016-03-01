package cn.edu.buaa.crypto.library.asgka;

import it.unisa.dia.gas.jpbc.Element;

public class ASGKAGroupEncryptionKey {
	private final Element R;
	private final Element A;
	
	public ASGKAGroupEncryptionKey(ASGKAGroupParameter param){
		//calculate R
		Element tempR = param.pairing().getG1().newOneElement();
		for (int i=0; i<param.n(); i++){
			tempR = tempR.mul(param.R_i(i));
		}
		this.R = tempR.duplicate().getImmutable();
		
		//calculate A
		Element tempA = param.pairing().getGT().newOneElement();
		for (int i=0; i<param.n(); i++){
			tempA = tempA.mul(param.A_i(i));
		}
		this.A = tempA.duplicate().getImmutable();
	}
	
	public Element R(){
		return this.R;
	}
	
	public Element A(){
		return this.A;
	}
}
