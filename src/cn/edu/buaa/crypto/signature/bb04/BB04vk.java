package cn.edu.buaa.crypto.signature.bb04;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class BB04vk {
	private Element g_1;
	private Element g_2;
	private Element u;
	private Element v;
	private Element z;
	
	public BB04vk(Pairing pairing, BB04sk sk){
		this.g_1 = sk.get_g_1().getImmutable();
		this.g_2 = pairing.getG2().newRandomElement().getImmutable();
		this.u = this.g_2.powZn(sk.get_x()).getImmutable();
		this.v = this.g_2.powZn(sk.get_y()).getImmutable();
		this.z = pairing.pairing(this.g_1, this.g_2);
	}
	
	public Element get_g_1(){
		return this.g_1.duplicate();
	}
	
	public Element get_g_2(){
		return this.g_2.duplicate();
	}
	
	public Element get_u(){
		return this.u.duplicate();
	}
	
	public Element get_v(){
		return this.v.duplicate();
	}
	
	public Element get_z(){
		return this.z.duplicate();
	}
	
	public byte[] getBytes(){
		byte[] byte_g_1 = this.g_1.toBytes();
		byte[] byte_g_2 = this.g_2.toBytes();
		byte[] byte_u = this.u.toBytes();
		byte[] byte_v = this.v.toBytes();
		byte[] byte_z = this.z.toBytes();
		byte[] result = new byte[byte_g_1.length + byte_g_2.length + byte_u.length + byte_v.length + byte_z.length];
		int tag = 0;
		System.arraycopy(byte_g_1, 0, result, tag, byte_g_1.length);
		tag += byte_g_1.length;
		System.arraycopy(byte_g_2, 0, result, tag, byte_g_2.length);
		tag += byte_g_2.length;
		System.arraycopy(byte_u, 0, result, tag, byte_u.length);
		tag += byte_u.length;
		System.arraycopy(byte_v, 0, result, tag, byte_v.length);
		tag += byte_v.length;
		System.arraycopy(byte_z, 0, result, tag, byte_z.length);
		return result;
		
	}
}
