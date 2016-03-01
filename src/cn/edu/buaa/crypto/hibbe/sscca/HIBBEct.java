package cn.edu.buaa.crypto.hibbe.sscca;

import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.library.llwrbac.LLWRBAC.LLWRBACType;
import cn.edu.buaa.crypto.signature.bb04.BB04;
import cn.edu.buaa.crypto.signature.bb04.BB04sign;
import cn.edu.buaa.crypto.signature.bb04.BB04sk;
import cn.edu.buaa.crypto.signature.bb04.BB04vk;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class HIBBEct {
	private final String[] roleVectorSet;
	private Element c_0;
	private Element c_1;
	private BB04vk vk;
	private BB04sign sign;
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
	
	public BB04vk get_vk(){
		return this.vk;
	}
	
	public BB04sign get_sign(){
		return this.sign;
	}
	
	public HIBBEct(HIBBEpp pp, String[] roleVectorSet){
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
		
		//For chosen ciphertext security
		Pairing pairingA = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);
		BB04sk sk = BB04.KeyGenSK(pairingA);
		this.vk = BB04.KeyGenVK(pairingA, sk);
		byte[] byte_vk = this.vk.getBytes();
		Element hash_vk = GroupHash.HashToZp(pp.get_pairing(), byte_vk);
		this.c_1 = this.c_1.mul(pp.get_u(pp.get_max_role()).powZn(hash_vk));
		this.c_1 = this.c_1.powZn(beta).getImmutable();
		
		byte[] byte_c_0 = this.c_0.toBytes();
		byte[] byte_c_1 = this.c_1.toBytes();
		byte[] byte_c_0_c_1 = new byte[byte_c_0.length + byte_c_1.length];
		System.arraycopy(byte_c_0, 0, byte_c_0_c_1, 0, byte_c_0.length);
		System.arraycopy(byte_c_1, 0, byte_c_0_c_1, byte_c_0.length, byte_c_1.length);
		this.sign = BB04.Signing(pairingA, sk, byte_c_0_c_1);
	}
}
