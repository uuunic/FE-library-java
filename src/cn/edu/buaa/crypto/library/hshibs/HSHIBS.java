package cn.edu.buaa.crypto.library.hshibs;

import org.bouncycastle.util.encoders.Hex;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.util.LibraryUtil;
import cn.edu.buaa.crypto.util.StdOut;

public class HSHIBS {
	private final Pairing pairing;
	private HSHIBSpp pp;
	
	public HSHIBS(){
		this.pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
	}
	
	public HSHIBSmsk Setup(){
		StdOut.println("HS-HIBS: System Setup.");
		this.pp = new HSHIBSpp(this.pairing);
		HSHIBSmsk msk = new HSHIBSmsk(this.pp);
		return msk;
	}
	
	public HSHIBSpp getPublicParameter(){
		return this.pp;
	}
	
	public HSHIBSsk KeyGen(HSHIBSpp pp, HSHIBSmsk msk, String ID_1){
		StdOut.println("HS-HIBS: Secret Key Generation secret key with Identity: " + ID_1);
		return new HSHIBSsk(pp, msk, ID_1);
	}
	
	public HSHIBSsk Delegate(HSHIBSpp pp, HSHIBSsk sk, String ID_t){
		HSHIBSsk sk_p = new HSHIBSsk(pp, sk, ID_t);
		String identityVector = LibraryUtil.IdentityVectorToString(sk_p.getID_t());
		StdOut.println("HS-HIBS: Secret Key Generation secret key with Identity Vector: " + identityVector);
		return sk_p;
	}
	
	public HSHIBSsign Signing(HSHIBSpp pp, HSHIBSsk sk, byte[] m){
		String identityVector = LibraryUtil.IdentityVectorToString(sk.getID_t());
		StdOut.println("HS-HIBS: Signing message using secret key with Identity Vector: " + identityVector);
		return new HSHIBSsign(pp, sk, m);
	}
	
	public boolean Verification(HSHIBSpp pp, HSHIBSsign sign){
		int depth = sign.get_depth();
		String[] ID_t = new String[depth];
		for (int i=0; i<ID_t.length; i++){
			ID_t[i] = sign.getID_t()[i];
		}
		Element[] h_i = new Element[depth];
		String concatID = "";
		for (int i=0; i<depth; i++){
			concatID = concatID.concat(ID_t[i]);
			h_i[i] = GroupHash.HashToG1(pp.getPairing(), concatID.getBytes()).getImmutable();
		}
		concatID = concatID.concat(Hex.toHexString(sign.get_m()));
		Element h_M = GroupHash.HashToG1(pp.getPairing(), concatID.getBytes()).getImmutable();
		
		
		Element temp1 = pp.getPairing().pairing(pp.get_g(), sign.get_sign()).getImmutable();
		
		Element temp2 = pp.getPairing().pairing(sign.get_v_i(depth), sign.get_h_M()).getImmutable();
		temp2 = temp2.mul(pp.getPairing().pairing(sign.get_v_i(0), h_i[0])).getImmutable();
		for (int i=1; i<depth; i++){
			temp2 = temp2.mul(pp.getPairing().pairing(sign.get_v_i(i), h_i[i])).getImmutable();
		}
		
		boolean result = temp1.equals(temp2);
		StdOut.println("HS-HIBS: Verification Result = " + result);
		return result;
	}
}
