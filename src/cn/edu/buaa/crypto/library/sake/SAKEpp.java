package cn.edu.buaa.crypto.library.sake;

import java.util.HashMap;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class SAKEpp {
	private final Element g;
	private final Pairing pairing;
	
	private HashMap<String[], Element> SignatureTable;
	
	public SAKEpp(Pairing pairing){
		this.pairing = pairing;
		this.g = this.pairing.getG1().newRandomElement().getImmutable();
		this.SignatureTable = new HashMap<String[], Element>();
	}
	
	public Pairing getPairing(){
		return this.pairing;
	}
	
	public Element get_g(){
		return this.g.duplicate();
	}
	
	public void addTable(String[] ID, Element u_a_p){
		this.SignatureTable.put(ID, u_a_p.duplicate());
	}
	
	public Element getTable(String[] ID){
		return this.SignatureTable.get(ID);
	}
}
