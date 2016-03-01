package cn.edu.buaa.crypto.hibbe.sscpa;

import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.util.StdOut;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SS_CPA_HIBBE {
	
	private final Pairing pairing;
	private HIBBEpp pp;
	
	public SS_CPA_HIBBE(){
		this.pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
	}
	
	public HIBBEpp getPublicParameter(){
		return this.pp;
	}
	
	public HIBBEmsk Setup(int D, int N){
		StdOut.println("Setup: System Setup.");
		Element alpha = pairing.getZr().newRandomElement().getImmutable();
		this.pp = new HIBBEpp(pairing, D, N, alpha);
		HIBBEmsk msk = new HIBBEmsk(this.pp, alpha);
		return msk;
	}
	
	public HIBBEsk KeyGen(HIBBEmsk msk, String[] roleVector){
		return new HIBBEsk(pp, msk, roleVector);
	}
	
	public HIBBEisk IKeyGen(){
		return new HIBBEisk(pp);
	}
	
	public HIBBEsk KeyGen(HIBBEmsk msk, String[] roleVector, HIBBEisk isk){
		return new HIBBEsk(pp, msk, roleVector, isk);
	}
	
	public HIBBEsk Delegate(HIBBEsk sk, String role){
		return new HIBBEsk(pp, sk, role);
	}
	
	public HIBBEsk Delegate(HIBBEsk sk, String role, HIBBEisk isk){
		return new HIBBEsk(pp, sk, role, isk);
	}
	
	public HIBBEct Encrypt(HIBBEpp pp, String[] roleVectorSet){
		return new HIBBEct(pp, roleVectorSet);
	}
	
	public Element Decrypt(HIBBEpp pp, HIBBEct ct, HIBBEsk sk){
		Element K = sk.get_a_0();
		for (int i=0; i<ct.get_role_vector_set().length; i++){
			boolean isInIndex = false;
			for (int j=0; j<sk.get_role_vector().length; j++){
				if (ct.get_role_vector_set()[i].equals(sk.get_role_vector()[j])){
					isInIndex = true;
				}
			}
			if (isInIndex){
				continue;
			}else{
				K.mul(sk.get_b(pp.get_role_manager().indexOf(ct.get_role_vector_set()[i])).powZn(pp.get_role_manager().hashOf(ct.get_role_vector_set()[i])));
			}
		}
		Element key = pairing.pairing(ct.get_c_1(), sk.get_a_1());
		key = key.div(pairing.pairing(K, ct.get_c_0()));
		System.out.println("[EHRDec]: random key is " + key);
		return key;
	}
}
