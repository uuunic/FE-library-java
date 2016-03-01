package cn.edu.buaa.crypto.signature.bb04;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class BB04sk {
	private Element g_1;
	private Element x;
	private Element y;
	
	public BB04sk(Pairing pairing){
		this.g_1 = pairing.getG1().newRandomElement().getImmutable();
		this.x = pairing.getZr().newRandomElement().getImmutable();
		this.y = pairing.getZr().newRandomElement().getImmutable();
	}
	
	public Element get_g_1(){
		return this.g_1.duplicate();
	}
	
	public Element get_x(){
		return this.x.duplicate();
	}
	
	public Element get_y(){
		return this.y.duplicate();
	}
}
