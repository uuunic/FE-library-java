package cn.edu.buaa.crypto.library.sake;

import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.library.hshibs.HSHIBSmsk;
import cn.edu.buaa.crypto.library.hshibs.HSHIBSpp;
import cn.edu.buaa.crypto.library.hshibs.HSHIBSsk;
import cn.edu.buaa.crypto.util.LibraryUtil;
import it.unisa.dia.gas.jpbc.Element;

public class SAKEsk {
	private final int depth;
	private final String[] ID_t;
	
	private final Element d_t;
	private final Element u_t;
	private final Element[] v_i;
	
	public SAKEsk (SAKEpp pp, SAKEmsk msk, String ID_1){
		this.depth = 1;
		this.ID_t = new String[this.depth];
		this.v_i = new Element[this.depth + 1];
		
		this.ID_t[0] = ID_1;
		Element h_t = GroupHash.HashToG1(pp.getPairing(), this.ID_t[0].getBytes()).getImmutable();
		
		this.d_t = pp.getPairing().getZr().newRandomElement().getImmutable();
		
		this.u_t = h_t.powZn(msk.get_d_0()).duplicate().getImmutable();
		
		this.v_i[0] = msk.get_v_0().getImmutable();
		this.v_i[1] = pp.get_g().powZn(this.d_t.duplicate()).getImmutable();
		
		Element u_t_p = pp.getPairing().pairing(pp.get_g(), this.u_t.mul(h_t.powZn(d_t.duplicate()))).getImmutable();
		pp.addTable(this.ID_t, u_t_p);
	}
	
	public SAKEsk (SAKEpp pp, SAKEsk sk, String ID_t){
		this.depth = sk.get_depth() + 1;
		this.ID_t = new String[this.depth];
		this.v_i = new Element[this.depth + 1];
		
		for (int i=0; i<sk.get_depth(); i++){
			this.ID_t[i] = sk.getID_t()[i];
		}
		this.ID_t[this.depth - 1] = ID_t;
		
		String concatID = LibraryUtil.concatStringArray(this.ID_t);
		Element h_t = GroupHash.HashToG1(pp.getPairing(), concatID.getBytes()).getImmutable();
		this.d_t = pp.getPairing().getZr().newRandomElement().getImmutable();
		this.u_t = h_t.powZn(sk.get_d_t()).mul(sk.get_u_t()).duplicate().getImmutable();
		
		for (int i=0; i<this.depth; i++){
			this.v_i[i] = sk.get_v_i(i).duplicate().getImmutable();
		}
		this.v_i[this.depth] = pp.get_g().powZn(this.d_t.duplicate()).getImmutable();
		
		Element u_t_p = pp.getPairing().pairing(pp.get_g(), this.u_t.mul(h_t.powZn(d_t.duplicate()))).getImmutable();
		pp.addTable(this.ID_t, u_t_p);
	}
	
	public int get_depth(){
		return this.depth;
	}
	
	public String[] getID_t(){
		return this.ID_t;
	}
	
	public Element get_d_t(){
		return this.d_t.duplicate();
	}
	
	public Element get_u_t(){
		return this.u_t.duplicate();
	}
	
	public Element get_v_i(int index){
		return this.v_i[index].duplicate();
	}
}
