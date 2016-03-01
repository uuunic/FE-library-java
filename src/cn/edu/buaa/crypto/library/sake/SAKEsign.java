package cn.edu.buaa.crypto.library.sake;

import org.bouncycastle.util.encoders.Hex;

import it.unisa.dia.gas.jpbc.Element;
import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.util.LibraryUtil;
import cn.edu.buaa.crypto.util.Timer;

public class SAKEsign {
	private final int depth;
	private final Element h_M;
	private final Element sign;
	private final String[] ID_t;
	private final Element v_t;
	private final byte[] m;
	private final String time;
	
	public SAKEsign(SAKEpp pp, SAKEsk sk, byte[] m){
		this.time = Timer.nowTime();
		this.depth = sk.get_depth();
		this.m = m;
		this.ID_t = sk.getID_t();
		
//		String concatID = LibraryUtil.concatStringArray(ID_t);
		String concatMessage = LibraryUtil.concatStringArray(ID_t);
		concatMessage = concatMessage.concat(Hex.toHexString(m));
		concatMessage = concatMessage.concat(time);
		
		this.h_M = GroupHash.HashToG1(pp.getPairing(), concatMessage.getBytes()).getImmutable();
		this.sign = sk.get_u_t().duplicate().mul(this.h_M.duplicate().powZn(sk.get_d_t().duplicate())).getImmutable();
		this.v_t = sk.get_v_i(this.depth).duplicate().getImmutable();
	}
	
	public Element get_h_M(){
		return this.h_M.duplicate();
	}
	
	public Element get_sign(){
		return this.sign.duplicate();
	}
	
	public Element get_v_t(){
		return this.v_t.duplicate();
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
	
	public String get_time(){
		return this.time;
	}
}
