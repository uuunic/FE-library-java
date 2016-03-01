package cn.edu.buaa.crypto.library.llwrbac;

import cn.edu.buaa.crypto.library.llwrbac.LLWRBAC.LLWRBACType;
import it.unisa.dia.gas.jpbc.Element;

public class LLWRBACct {
	private final String[] roleVectorSet;
	private Element c_0;
	private Element c_1;
	private transient Element key;
	
	public Element get_c_0(){
		return this.c_0.duplicate();
	}
	
	public Element get_c_1(){
		return this.c_1.duplicate();
	}
	
	public Element get_key(){
		return this.key.duplicate();
	}
	
	public String[] get_role_vector_set(){
		return this.roleVectorSet;
	}
	
	public LLWRBACct(LLWRBACpp pp, String[] roleVectorSet){
		this.roleVectorSet = roleVectorSet;
		Element beta = pp.get_pairing().getZr().newRandomElement().getImmutable();
		//compute c_0
		this.c_0 = pp.get_g().powZn(beta).getImmutable();
		
		//compute c_2
		this.key = pp.get_pairing().pairing(pp.get_g_1(), pp.get_g_2()).powZn(beta).getImmutable();
		System.out.println("[LLWRBACct]: random key = " + this.key);
				
		//compute c_1
		this.c_1 = pp.get_g_3().duplicate();
		for (int i=0; i<this.roleVectorSet.length; i++){
			int index = pp.get_role_manager().indexOf(roleVectorSet[i]);
			this.c_1 = this.c_1.mul(pp.get_u(index).powZn(pp.get_role_manager().hashOf(this.roleVectorSet[i])));
		}
		if (pp.getType() == LLWRBACType.CCASecure){
			byte[] byte_c_0 = this.c_0.toBytes();
			Element hash_c_0_c_2 = pp.get_pairing().getZr().newElement().setFromHash(byte_c_0, 0, byte_c_0.length);
			this.c_1 = this.c_1.mul(pp.get_u(pp.get_max_role()).powZn(hash_c_0_c_2));
		}
		this.c_1 = this.c_1.powZn(beta).getImmutable();
	}
}
