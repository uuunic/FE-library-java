package cn.edu.buaa.crypto.library.llwcpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class LLWCPABEpp {
	private final Pairing pairing;
	private final Element g;
	private final Element h;
	private final Element u;
	private final Element v;
	private final Element w;
	private final Element hat_alpha;
	
	public LLWCPABEpp(Pairing pairing, Element alpha){
		this.pairing = pairing;
		this.g = pairing.getG1().newRandomElement().getImmutable();
		this.h = pairing.getG1().newRandomElement().getImmutable();
		this.u = pairing.getG1().newRandomElement().getImmutable();
		this.v = pairing.getG1().newRandomElement().getImmutable();
		this.w = pairing.getG1().newRandomElement().getImmutable();
		this.hat_alpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
	}
	
	public Element g(){
		return this.g.duplicate();
	}
	
	public Element h(){
		return this.h.duplicate();
	}
	
	public Element u(){
		return this.u.duplicate();
	}
	
	public Element v(){
		return this.v.duplicate();
	}
	
	public Element w(){
		return this.w.duplicate();
	}
	
	public Element hat_alpha(){
		return this.hat_alpha.duplicate();
	}
	
	public Pairing getPairing(){
		return this.pairing;
	}
}
