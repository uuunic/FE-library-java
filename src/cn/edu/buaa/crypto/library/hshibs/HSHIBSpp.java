package cn.edu.buaa.crypto.library.hshibs;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class HSHIBSpp {
	private final Element g;
	private final Pairing pairing;
	
	public HSHIBSpp(Pairing pairing){
		this.pairing = pairing;
		this.g = this.pairing.getG1().newRandomElement().getImmutable();
	}
	
	public Pairing getPairing(){
		return this.pairing;
	}
	
	public Element get_g(){
		return this.g.duplicate();
	}
}
