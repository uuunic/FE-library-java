package cn.edu.buaa.crypto.abe.cca2kpabe;

public class CCA2KPABEsk {
	private final CCA2KPABEPolicyNode rootNode;
	
	public CCA2KPABEsk(CCA2KPABEpp pp, CCA2KPABEmsk msk, String policy){	
		this.rootNode = CCA2KPABEPolicyNode.parsePolicy(pp.getPairing(), policy);
		CCA2KPABEPolicyNode.sharePolicy(pp, rootNode, msk.alpha());
	}
	
	public void KeyGen(CCA2KPABEpp pp, CCA2KPABEmsk msk){
		CCA2KPABEPolicyNode.fillPolicy(pp, this.rootNode);
	}
	
	public CCA2KPABEPolicyNode getPolicyTree(){
		return this.rootNode;
	}
}
