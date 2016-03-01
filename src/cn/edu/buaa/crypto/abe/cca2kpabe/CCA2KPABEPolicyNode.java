package cn.edu.buaa.crypto.abe.cca2kpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Stack;

import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.algs.Polynomial;

public class CCA2KPABEPolicyNode {
	
	public static CCA2KPABEPolicyNode parsePolicy(Pairing pairing, String policy){
		String[] fields = policy.trim().split("\\s+");
		int curse = 0;
		Stack<CCA2KPABEPolicyNode> stack = new Stack<CCA2KPABEPolicyNode>();
		while (curse < fields.length){
			String toks = fields[curse];
			curse++;
			if (!toks.contains("-")){
				stack.push(new CCA2KPABEPolicyNode(pairing, toks));
				continue;
			} else {
				String[] thresholdGates = toks.split("-");
				int k = Integer.valueOf(thresholdGates[0]);
				int n = Integer.valueOf(thresholdGates[1]);
				if (k < 1){
					throw new RuntimeException("error parsing " + toks + ": k less than 1");
				} else if (k > n){
					throw new RuntimeException("error parsing " + toks + "k larger than n");
				} else if (n == 0){
					throw new RuntimeException("error parsing " + toks + ": n equals 0");
				} else if (n > stack.size()){
					throw new RuntimeException("error parsing " + toks + ": n larger than remaining attrs");
				}
				CCA2KPABEPolicyNode[] children = new CCA2KPABEPolicyNode[n];
				for (int i = n-1; i>=0; i--){
					children[i] = stack.pop();
				}
				stack.push(new CCA2KPABEPolicyNode(k, n, children));
			}
		}
		if (stack.size() > 1){
			throw new RuntimeException("error parsing " + stack.size() + "extra tokens left on stack");
		} else if (stack.size() < 1){
			throw new RuntimeException("error parsing " + stack.size() + "stack empty");
		}
		CCA2KPABEPolicyNode root = stack.pop();
		return root;
	}
	
	
	//k == 1 if leaf. Otherwise, it is a threshold;
	private final int k;
	//number of children. n == 0 if leaf.
	private final int n;
	//attribute string if leaf. Otherwise null;
	private final String attribute;
	
	public String attribute(){
		return this.attribute;
	}
	
	private final Element A_i;
	//PolicyNode children, length = 0 for leaves;
	private final CCA2KPABEPolicyNode[] children;
	//K_1, K_2, K_3, only for leaves;
	private Element K_1;
	
	public Element K_1(){
		return this.K_1.duplicate();
	}
	
	private Element K_2;
	
	public Element K_2(){
		return this.K_2.duplicate();
	}
	private Element K_3;
	
	public Element K_3(){
		return this.K_3.duplicate();
	}
	
	//Lagrange Polynomial for the Node. Only used during encryption
	private transient Polynomial polynomial;
	private transient Element share;
	
	//only used during decryption
	private transient boolean satisfiable;
	private transient int satisfyNum;
	private transient Element C_0;
	private transient Element C_i_1;
	private transient Element C_i_2;
	private transient Element decryptNodeResult;
	
	/**
	 * Constructing a leaf node.
	 * @param attribute
	 */
	private CCA2KPABEPolicyNode (Pairing pairing, String attribute){
		this.k = 1;
		this.n = 0;
		this.attribute = attribute;
		this.A_i = GroupHash.HashToZp(pairing, attribute.getBytes()).getImmutable();
		this.children = new CCA2KPABEPolicyNode[this.n];
		this.polynomial = null;
	}
	
	/**
	 * constructing a threshold node.
	 * @param k threshold.
	 * @param n number of children.
	 */
	private CCA2KPABEPolicyNode (int k, int n, CCA2KPABEPolicyNode[] children){
		assert(k <= n);
		this.k = k;
		this.n = n;
		this.attribute = null;
		this.A_i = null;
		this.children = children;
	}
	
	public boolean isLeaf(){
		return children.length == 0;
	}
	
	public int getThreshold(){
		return this.k;
	}
	
	public int getNumChildren(){
		return this.children.length;
	}
	
	public CCA2KPABEPolicyNode getChildrenAt(int index){
		assert(index < this.n);
		return this.children[index];
	}
	
	public static void sharePolicy(CCA2KPABEpp pp, CCA2KPABEPolicyNode node, Element e){
		Element indexElement;
		Element shareElement;
		
		if (node.isLeaf()){
			//Generate ciphertext components
			node.share = e.duplicate().getImmutable();
		} else {
			//Note leaf, share the secret
			node.polynomial = new Polynomial(pp.getPairing(), node.k - 1, e.duplicate());
			for (int i=1; i<= node.n; i++){
				indexElement = pp.getPairing().getZr().newElement(i).getImmutable();
				shareElement = node.polynomial.evaluate(indexElement).getImmutable();
				sharePolicy(pp, node.getChildrenAt(i-1), shareElement);
			}
		}
	}
	
	public static void fillPolicy(CCA2KPABEpp pp, CCA2KPABEPolicyNode node){
		Element t_i;
		
		t_i = pp.getPairing().getZr().newRandomElement().getImmutable();
		
		if (node.isLeaf()){
			//Generate ciphertext components
			node.K_1 = pp.g().powZn(node.share.duplicate()).mul(pp.w().powZn(t_i.duplicate()));
			node.K_2 = pp.u().powZn(node.A_i.duplicate()).mul(pp.h()).invert().powZn(t_i.duplicate());
			node.K_3 = pp.g().powZn(t_i.duplicate());
		} else {
			//Note leaf, share the secret
			for (int i=1; i<= node.n; i++){
				fillPolicy(pp, node.getChildrenAt(i-1));
			}
		}
	}
	
	private static void checkSatesfiable(CCA2KPABEct ct, CCA2KPABEPolicyNode node){
		node.satisfiable = false;
		if (node.isLeaf()){
			for (int i=0; i<ct.numOfAttrs(); i++){
				CCA2KPABEct.CCA2KPABEctComps ctComps = ct.ctComps(i);
				if (node.attribute.equals(ctComps.attribute())){
					node.satisfiable = true;
					//fill in the secret key
					node.C_0 = ct.C_0().duplicate().getImmutable();
					node.C_i_1 = ctComps.C_1().duplicate().getImmutable();
					node.C_i_2 = ctComps.C_2().duplicate().getImmutable();
				}
			}
			return;
		} else {
			//Not leaf, traversal the access tree
			for (int i=0; i < node.n; i++){
				CCA2KPABEPolicyNode.checkSatesfiable(ct, node.getChildrenAt(i));
			}
			int l = 0;
			for (int i=0; i < node.n; i++){
				if (node.getChildrenAt(i).satisfiable){
					l++;
				}
			}
			node.satisfyNum = l;
			if (l >= node.k){
				node.satisfiable = true;
			}
		}
	}
	
	private static void decryptLeaf(CCA2KPABEpp pp, CCA2KPABEPolicyNode node){
		assert(node.isLeaf());
		Element temp1 = pp.getPairing().pairing(node.C_0, node.K_1()).getImmutable();
		Element temp2 = pp.getPairing().pairing(node.C_i_1, node.K_2()).getImmutable();
		Element temp3 = pp.getPairing().pairing(node.C_i_2, node.K_3()).getImmutable();
		node.decryptNodeResult = temp1.mul(temp2).mul(temp3).getImmutable();
	}
	
	private static void decryptInternal(CCA2KPABEpp pp, CCA2KPABEPolicyNode node){
		if (node.isLeaf()){
			CCA2KPABEPolicyNode.decryptLeaf(pp, node);
		} else {
			node.decryptNodeResult = pp.getPairing().getGT().newOneElement().getImmutable();
			for (int i=0; i<node.n; i++){
				if (node.getChildrenAt(i).satisfiable){
					CCA2KPABEPolicyNode.decryptInternal(pp, node.getChildrenAt(i));
				}
			}
			int[] set = new int[node.satisfyNum];
			int label = 0;
			for (int i=0; i<node.n; i++){
				if (node.getChildrenAt(i).satisfiable){
					set[label] = i+1;
					label++;
				}
			}
			for (int i=0; i<node.n; i++){
				if (node.getChildrenAt(i).satisfiable){
					Element w_i = Polynomial.calCoef(pp.getPairing(), set, i+1);
					node.decryptNodeResult = node.decryptNodeResult.mul(node.getChildrenAt(i).decryptNodeResult.powZn(w_i)).getImmutable();
				}
			}
		}
	}
	
	public static Element decrypt(CCA2KPABEpp pp, CCA2KPABEct ct, CCA2KPABEPolicyNode rootNode){
		CCA2KPABEPolicyNode.checkSatesfiable(ct, rootNode);
		if (!rootNode.satisfiable){
			return null;
		}
		CCA2KPABEPolicyNode.decryptInternal(pp, rootNode);
		return rootNode.decryptNodeResult;
	}
}
