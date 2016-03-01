package cn.edu.buaa.crypto.library.hshibs;

import org.bouncycastle.util.encoders.Hex;

import cn.edu.buaa.crypto.algs.GroupHash;
import it.unisa.dia.gas.jpbc.Element;

public class HSHIBSsign {
	private final int depth;
	private final Element h_M;
	private final Element sign;
	private final String[] ID_t;
	private final Element[] v_i;
	private final byte[] m;
	
	public HSHIBSsign(HSHIBSpp pp, HSHIBSsk sk, byte[] message){
		this.depth = sk.get_depth();
		this.m = message;
		this.ID_t = new String[this.depth];
		for (int i=0; i<sk.getID_t().length; i++){
			ID_t[i] = sk.getID_t()[i];
		}
		Element[] h_i = new Element[this.depth];
		String concatID = "";
		for (int i=0; i<sk.getID_t().length; i++){
			concatID = concatID.concat(this.ID_t[i]);
			h_i[i] = GroupHash.HashToG1(pp.getPairing(), concatID.getBytes()).getImmutable();
		}
		concatID = concatID.concat(Hex.toHexString(m));
		this.h_M = GroupHash.HashToG1(pp.getPairing(), concatID.getBytes()).getImmutable();
		this.sign = sk.get_u_t().duplicate().mul(this.h_M.duplicate().powZn(sk.get_d_t().duplicate())).getImmutable();
		this.v_i = new Element[this.depth + 1];
		for (int i=0; i<this.v_i.length; i++){
			this.v_i[i] = sk.get_v_i(i).duplicate().getImmutable();
		}
	}
	
	public Element get_h_M(){
		return this.h_M.duplicate();
	}
	
	public Element get_sign(){
		return this.sign.duplicate();
	}
	
	public Element get_v_i(int index){
		return this.v_i[index].duplicate();
	}
	
	public String[] getID_t(){
		return this.ID_t;
	}
	
	public int get_depth(){
		return this.depth;
	}
	
	public byte[] get_m(){
		return this.m;
	}
}
