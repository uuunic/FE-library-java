package cn.edu.buaa.crypto.abe.cca2kpabe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import it.unisa.dia.gas.jpbc.Element;
import cn.edu.buaa.crypto.abe.Type;
import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.algs.ChameleonHash.HashData;
import cn.edu.buaa.crypto.util.StdOut;

public class CCA2KPABEct {
//	private final Pairing pairing;
	private final Element C_0;
	private transient Element key;
	
	public Element C_0(){
		return this.C_0.duplicate();
	}
	
	//For validity Verification
	private Element C_0_1;
		
	public Element C_0_1(){
		return this.C_0_1.duplicate();
	}
		
	private Element C_0_2;
	
	public Element C_0_2(){
		return this.C_0_2.duplicate();
	}
	
	private final CCA2KPABEctComps[] ctComps;
	private final int numOfAttrs;
	
	private Element rChameleonHash;
	
	public Element rChameleonHash(){
		return this.rChameleonHash.duplicate();
	}
	
	public CCA2KPABEct(CCA2KPABEpp pp, String[] attrs){
		Element s = pp.getPairing().getZr().newRandomElement().getImmutable();
		this.C_0 = pp.g().powZn(s).getImmutable();
		this.numOfAttrs = attrs.length;
		ctComps = new CCA2KPABEctComps[numOfAttrs];
		
		for (int i=0; i<numOfAttrs; i++){
			ctComps[i] = new CCA2KPABEctComps(pp, attrs[i], s);
		}
		this.key = pp.hat_alpha().powZn(s.duplicate()).getImmutable();
		StdOut.println("LLWCPABE Encrypt: Encapsulated Key = " + key);
		
		if (pp.getType() == Type.CCA2){
			Element r_0 = pp.getPairing().getZr().newRandomElement().getImmutable();
			this.C_0_1 = pp.g().powZn(r_0).getImmutable();
			HashData hashData = pp.getChameleonHash().setHashData(CCA2KPABEct.getVerifyAttribute(this));
			Element verificationAttribute = pp.getChameleonHash().hashVerification(pp.get_gChameleonHash(), pp.get_hChameleonHash(), hashData).getImmutable();
			this.rChameleonHash = hashData.getR().duplicate().getImmutable();
			this.C_0_2 = pp.u().powZn(verificationAttribute).mul(pp.h()).powZn(r_0.duplicate()).mul(pp.w().invert().powZn(s)).getImmutable();
		}
	}
	
	public static boolean Audit(CCA2KPABEpp pp, CCA2KPABEct ct){
		if (pp.getType() == Type.CPA){
			return true;
		}
		for (int i=0; i<ct.numOfAttrs; i++){
			CCA2KPABEctComps ctComps = ct.ctComps(i);
			if (!pp.getPairing().pairing(pp.g(), ctComps.C_2()).mul(pp.getPairing().pairing(ctComps.C_1(), pp.u().powZn(ctComps.A()).mul(pp.h())).invert()).mul(pp.getPairing().pairing(ct.C_0(), pp.w())).equals(pp.getPairing().getGT().newOneElement())){
				return false;
			}
		}
		HashData hashData = pp.getChameleonHash().setHashData(CCA2KPABEct.getVerifyAttribute(ct), ct.rChameleonHash());
		Element verificationAttribute = pp.getChameleonHash().hashVerification(pp.get_gChameleonHash(), pp.get_hChameleonHash(), hashData).getImmutable();
		//Test Verification Attribute
		if (!pp.getPairing().pairing(pp.g(), ct.C_0_2()).mul(pp.getPairing().pairing(ct.C_0_1(), pp.u().powZn(verificationAttribute).mul(pp.h())).invert()).mul(pp.getPairing().pairing(ct.C_0(), pp.w())).equals(pp.getPairing().getGT().newOneElement())){
			return false;
		}
		return true;
	}
	
	public int numOfAttrs(){
		return this.numOfAttrs;
	}
	
	public CCA2KPABEctComps ctComps(int index){
		assert(index < this.numOfAttrs);
		return this.ctComps[index];
	}
	
	private static ArrayList<Element> combineCTComps(CCA2KPABEct ct){
		ArrayList<Element> combinedElements = new ArrayList<Element>();
		for (int i=0; i<ct.numOfAttrs; i++){
			CCA2KPABEctComps ctComps = ct.ctComps(i);
			combinedElements.add(ctComps.C_1());
			combinedElements.add(ctComps.C_2());
		}
		combinedElements.add(ct.C_0_1());
		return combinedElements;
	}
	
	public static byte[] getVerifyAttribute(CCA2KPABEct ct){
		try {
			ArrayList<Element> combineCTComps = CCA2KPABEct.combineCTComps(ct);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			for (Element element: combineCTComps){
				out.write(element.toBytes());
			}
			return out.toByteArray();
		}  catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
	
	public class CCA2KPABEctComps{
		//attribute for that component
		private final String attribute;
		private final Element A_i;
		//elements for that component, C_1, C_2
		private final Element C_1;
		private final Element C_2;
		
		public CCA2KPABEctComps(CCA2KPABEpp pp, String attribute, Element s){
			this.attribute = attribute;
			Element r_i = pp.getPairing().getZr().newRandomElement().getImmutable();
			this.C_1 = pp.g().powZn(r_i.duplicate()).getImmutable();
			this.A_i = GroupHash.HashToZp(pp.getPairing(), attribute.getBytes()).getImmutable();
			this.C_2 = pp.u().powZn(A_i).mul(pp.h()).powZn(r_i.duplicate()).mul(pp.w().invert().powZn(s.duplicate())).getImmutable();
		}
		
		public String attribute(){
			return this.attribute;
		}
		
		public Element C_1(){
			return this.C_1.duplicate();
		}
		
		public Element C_2(){
			return this.C_2.duplicate();
		}
		
		public Element A(){
			return this.A_i.duplicate();
		}
	}
}
