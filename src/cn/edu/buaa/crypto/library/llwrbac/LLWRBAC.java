package cn.edu.buaa.crypto.library.llwrbac;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import cn.edu.buaa.crypto.algs.GeneralHash;
import cn.edu.buaa.crypto.algs.SymmetricBlockEnc;
import cn.edu.buaa.crypto.algs.GeneralHash.HashMode;
import cn.edu.buaa.crypto.algs.SymmetricBlockEnc.Mode;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.util.StdOut;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class LLWRBAC {
	public enum LLWRBACType{
		CPASecure, CCASecure,
	}
	
	private final Pairing pairing;
	private LLWRBACpp pp;
	
	public LLWRBAC(){
		this.pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
	}
	
	public LLWRBACpp getPublicParameter(){
		return this.pp;
	}
	
	public LLWRBACmsk SetupCCASecure(int D, int N){
		Element alpha = pairing.getZr().newRandomElement().getImmutable();
		this.pp = new LLWRBACpp(pairing, LLWRBACType.CCASecure, D, N, alpha);
		LLWRBACmsk msk = new LLWRBACmsk(this.pp, alpha);
		return msk;
	}
	
	public LLWRBACmsk SetupCPASecure(int D, int N){
		StdOut.println("Setup: System Setup.");
		Element alpha = pairing.getZr().newRandomElement().getImmutable();
		this.pp = new LLWRBACpp(pairing, LLWRBACType.CPASecure, D, N, alpha);
		LLWRBACmsk msk = new LLWRBACmsk(this.pp, alpha);
		return msk;
	}
	
	public LLWRBACac ACGen(LLWRBACmsk msk, String[] roleVector){
		return new LLWRBACac(pp, msk, roleVector);
	}
	
	public LLWRBACiac IACGen(){
		return new LLWRBACiac(pp);
	}
	
	public LLWRBACac ACGen(LLWRBACmsk msk, String[] roleVector, LLWRBACiac iac){
		return new LLWRBACac(pp, msk, roleVector, iac);
	}
	
	public LLWRBACac ACDelegate(LLWRBACac ac, String role){
		return new LLWRBACac(pp, ac, role);
	}
	
	public LLWRBACac ACDelegate(LLWRBACac ac, String role, LLWRBACiac iac){
		return new LLWRBACac(pp, ac, role, iac);
	}
	
	public LLWRBACct EHREnc(LLWRBACpp pp, String[] roleVectorSet){
		return new LLWRBACct(pp, roleVectorSet);
	}
	
	public LLWRBACct EHREnc(LLWRBACpp pp, String[] roleVectorSet, File fileIn, File fileOut){
		try{
			LLWRBACct ct = new LLWRBACct(pp, roleVectorSet);
			FileInputStream in = new FileInputStream(fileIn);
			FileOutputStream out = new FileOutputStream(fileOut);
			SymmetricBlockEnc.enc_AES(Mode.CBC, GeneralHash.Hash(HashMode.SHA256, ct.get_key().toBytes()), SymmetricBlockEnc.InitVector, in, out);
			in.close();
			out.close();
			return ct;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new RuntimeException();
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
	
	public boolean Audit(LLWRBACpp pp, LLWRBACct ct){
		byte[] byte_c_0 = ct.get_c_0().toBytes();
		Element hash_c_0_c_2 = pairing.getZr().newElement().setFromHash(byte_c_0, 0, byte_c_0.length);
		if (pp.getType() == LLWRBACType.CCASecure){
			//Ciphertext Validity Test
			Element role_random = pp.get_g_3();
			for (int i=0; i<ct.get_role_vector_set().length; i++){
				role_random = role_random.mul(pp.get_role_manager().uPowerOf(ct.get_role_vector_set()[i]));
			}
			role_random = role_random.mul(pp.get_u(pp.get_max_role()).powZn(hash_c_0_c_2));
			Element temp1 = pairing.pairing(pp.get_g(), ct.get_c_1());
			Element temp2 = pairing.pairing(ct.get_c_0(), role_random);
			
			if(!temp1.equals(temp2)){
				System.out.println("[Audit]: e(g, c_1) = " + temp1);
				System.out.println("[Audit]: e(c_0, r) = " + temp2);
				System.out.println("[Audit]: verify equation do not pass, this is an invalid ciphertext");
				return false;
			}
		}
		System.out.println("[Audit]: verify equation passes, this is an valid ciphertext");
		return true;
	}
	
	public Element EHRDec(LLWRBACpp pp, LLWRBACct ct, LLWRBACac ac){
		byte[] byte_c_0 = ct.get_c_0().toBytes();
		Element hash_c_0_c_2 = pairing.getZr().newElement().setFromHash(byte_c_0, 0, byte_c_0.length);
		Element K = ac.get_a_0();
		for (int i=0; i<ct.get_role_vector_set().length; i++){
			boolean isInIndex = false;
			for (int j=0; j<ac.get_role_vector().length; j++){
				if (ct.get_role_vector_set()[i].equals(ac.get_role_vector()[j])){
					isInIndex = true;
				}
			}
			if (isInIndex){
				continue;
			}else{
				K.mul(ac.get_b(pp.get_role_manager().indexOf(ct.get_role_vector_set()[i])).powZn(pp.get_role_manager().hashOf(ct.get_role_vector_set()[i])));
			}
		}
		if (pp.getType() == LLWRBACType.CCASecure){
			K = K.mul(ac.get_b(pp.get_max_role()).powZn(hash_c_0_c_2));
		}
		Element key = pairing.pairing(ct.get_c_1(), ac.get_a_1());
		key = key.div(pairing.pairing(K, ct.get_c_0()));
		System.out.println("[EHRDec]: random key is " + key);
		return key;
	}
	
	public void EHRDec(LLWRBACpp pp, LLWRBACct ct, LLWRBACac ac, File fileIn, File fileOut){
		Element key = EHRDec(pp, ct, ac);
		try{
			FileInputStream in = new FileInputStream(fileIn);
			FileOutputStream out = new FileOutputStream(fileOut);
			SymmetricBlockEnc.dec_AES(Mode.CBC, GeneralHash.Hash(HashMode.SHA256, key.toBytes()), SymmetricBlockEnc.InitVector, in, out);
			in.close();
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new RuntimeException();
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
}
