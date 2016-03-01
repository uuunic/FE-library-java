package cn.edu.buaa.crypto.signature.bb04;

import cn.edu.buaa.crypto.algs.GroupHash;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class BB04sign {
	private Element sigma;
	private Element r;
	private Element hashMessage;
	
	public BB04sign(Pairing pairing, BB04sk sk, byte[] message){
		this.hashMessage = GroupHash.HashToZp(pairing, message).getImmutable();
		this.r = pairing.getZr().newRandomElement().getImmutable();
		Element exponent = sk.get_x().add(hashMessage).add(sk.get_y().mul(this.r)).invert();
		this.sigma = sk.get_g_1().powZn(exponent).getImmutable();
	}
	
	public Element get_sigma(){
		return this.sigma;
	}
	
	public Element get_r(){
		return this.r;
	}
	
	public Element get_hash_message(){
		return this.hashMessage;
	}
}
