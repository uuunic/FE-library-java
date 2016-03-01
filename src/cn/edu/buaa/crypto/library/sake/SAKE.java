package cn.edu.buaa.crypto.library.sake;

import org.bouncycastle.util.encoders.Hex;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.library.hshibs.HSHIBSmsk;
import cn.edu.buaa.crypto.library.hshibs.HSHIBSpp;
import cn.edu.buaa.crypto.library.hshibs.HSHIBSsign;
import cn.edu.buaa.crypto.library.hshibs.HSHIBSsk;
import cn.edu.buaa.crypto.util.LibraryUtil;
import cn.edu.buaa.crypto.util.StdOut;

public class SAKE {
	private final Pairing pairing;
	private SAKEpp pp;
	
	public SAKE(){
		this.pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
	}
	
	public SAKEmsk Setup(){
		StdOut.println("HS-HIBS: System Setup.");
		this.pp = new SAKEpp(this.pairing);
		SAKEmsk msk = new SAKEmsk(this.pp);
		return msk;
	}
	
	public SAKEpp getPublicParameter(){
		return this.pp;
	}
	
	public SAKEsk KeyGen(SAKEpp pp, SAKEmsk msk, String ID_1){
		StdOut.println("SAKE: Secret Key Generation secret key with Identity: " + ID_1);
		return new SAKEsk(pp, msk, ID_1);
	}
	
	public SAKEsk Delegate(SAKEpp pp, SAKEsk sk, String ID_t){
		SAKEsk sk_p = new SAKEsk(pp, sk, ID_t);
		String identityVector = LibraryUtil.IdentityVectorToString(sk_p.getID_t());
		StdOut.println("SAKE: Secret Key Generation secret key with Identity Vector: " + identityVector);
		return sk_p;
	}
	
	public SAKEsign Signing(SAKEpp pp, SAKEsk sk, byte[] m){
		String identityVector = LibraryUtil.IdentityVectorToString(sk.getID_t());
		StdOut.println("SAKE: Signing message using secret key with Identity Vector: " + identityVector);
		return new SAKEsign(pp, sk, m);
	}
	
	public boolean Verification(SAKEpp pp, SAKEsign sign){
		String[] ID_t = sign.getID_t();
		
		String concatID = LibraryUtil.concatStringArray(ID_t);
		String concatMessage = LibraryUtil.concatStringArray(ID_t);
		concatMessage = concatMessage.concat(Hex.toHexString(sign.get_m()));
		concatMessage = concatMessage.concat(sign.get_time());
		
		Element h_A = GroupHash.HashToG1(pp.getPairing(), concatID.getBytes()).getImmutable();
		Element h_A_p = GroupHash.HashToG1(pp.getPairing(), concatMessage.getBytes()).getImmutable();
		
		Element temp1 = pp.getPairing().pairing(pp.get_g(), sign.get_sign()).getImmutable();
		
		Element temp2 = pp.getTable(ID_t).getImmutable();
		
		Element temp3 = pp.getPairing().pairing(sign.get_v_t(), h_A_p).getImmutable();
		
		Element temp4 = pp.getPairing().pairing(sign.get_v_t(), h_A).invert().getImmutable();
		
		temp2 = temp2.mul(temp3).mul(temp4).getImmutable();
		
		boolean result = temp1.equals(temp2);
		StdOut.println("HS-HIBS: Verification Result = " + result);
		return result;
	}
}
