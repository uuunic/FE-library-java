package cn.edu.buaa.crypto.abe.cca2cpabe;

import cn.edu.buaa.crypto.abe.Type;
import cn.edu.buaa.crypto.algs.LLWChameleonHash;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class CCA2CPABEpp {
	private final Pairing pairing;
	private final Element g;
	private final Element h;
	private final Element u;
	private final Element v;
	private final Element w;
	private final Element hat_alpha;
	private final Type type;
	
	//Chameleon hash function;
	private LLWChameleonHash chameleonHash;
	private Element gChameleonHash;
	private Element hChameleonHash;
	
	public CCA2CPABEpp(Pairing pairing, Type type, Element alpha){
		this.pairing = pairing;
		this.type = type;
		this.g = pairing.getG1().newRandomElement().getImmutable();
		this.h = pairing.getG1().newRandomElement().getImmutable();
		this.u = pairing.getG1().newRandomElement().getImmutable();
		this.v = pairing.getG1().newRandomElement().getImmutable();
		this.w = pairing.getG1().newRandomElement().getImmutable();
		this.hat_alpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
		
		if (this.type == Type.CCA2){
			//generate ChameleonHash keys
			this.chameleonHash = new LLWChameleonHash(pairing);
			LLWChameleonHash.Keys keys = chameleonHash.keyGen();
			this.gChameleonHash = keys.getG().duplicate().getImmutable();
			this.hChameleonHash = keys.getH().duplicate().getImmutable();
		}
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
	
	public Type getType(){
		return this.type;
	}
	
	public Element get_gChameleonHash(){
		return this.gChameleonHash.duplicate();
	}
	
	public Element get_hChameleonHash(){
		return this.hChameleonHash.duplicate();
	}
	
	public LLWChameleonHash getChameleonHash(){
		return this.chameleonHash;
	}
}
