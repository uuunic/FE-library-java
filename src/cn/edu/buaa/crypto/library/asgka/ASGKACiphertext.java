package cn.edu.buaa.crypto.library.asgka;

import cn.edu.buaa.crypto.util.StdOut;
import it.unisa.dia.gas.jpbc.Element;

public class ASGKACiphertext {
	private final Element c_1;
	private final Element c_2;
	private final Element c_3;
	
	public ASGKACiphertext(ASGKAGroupParameter param, ASGKAGroupEncryptionKey key, Element m){
//		Element m = param.pairing().getGT().newRandomElement().getImmutable();
		Element t = param.pairing().getZr().newRandomElement().getImmutable();
		this.c_1 = param.g().powZn(t.duplicate()).getImmutable();
		this.c_2 = key.R().powZn(t.duplicate()).getImmutable();
		this.c_3 = key.A().powZn(t.duplicate()).mul(m.duplicate()).getImmutable();
	}
	
	public Element c_1(){
		return this.c_1.duplicate();
	}
	
	public Element c_2(){
		return this.c_2.duplicate();
	}
	
	public Element c_3(){
		return this.c_3.duplicate();
	}
}
