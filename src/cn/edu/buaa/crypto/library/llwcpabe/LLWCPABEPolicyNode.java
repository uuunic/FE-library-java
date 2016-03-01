package cn.edu.buaa.crypto.library.llwcpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Stack;

import cn.edu.buaa.crypto.algs.GroupHash;
import cn.edu.buaa.crypto.algs.Polynomial;
import cn.edu.buaa.crypto.util.StdOut;

public class LLWCPABEPolicyNode implements Serializable{
	
	public static LLWCPABEPolicyNode parsePolicy(Pairing pairing, String policy){
		String[] fields = policy.trim().split("\\s+");
		int curse = 0;
		Stack<LLWCPABEPolicyNode> stack = new Stack<LLWCPABEPolicyNode>();
		while (curse < fields.length){
			String toks = fields[curse];
			curse++;
			if (!toks.contains("-")){
				stack.push(new LLWCPABEPolicyNode(pairing, toks));
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
				LLWCPABEPolicyNode[] children = new LLWCPABEPolicyNode[n];
				for (int i = n-1; i>=0; i--){
					children[i] = stack.pop();
				}
				stack.push(new LLWCPABEPolicyNode(k, n, children));
			}
		}
		if (stack.size() > 1){
			throw new RuntimeException("error parsing " + stack.size() + "extra tokens left on stack");
		} else if (stack.size() < 1){
			throw new RuntimeException("error parsing " + stack.size() + "stack empty");
		}
		LLWCPABEPolicyNode root = stack.pop();
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
	private final LLWCPABEPolicyNode[] children;
	//C_1, C_2, C_3, C_4, C_5, only for leaves;
	private Element C_1;
	
	public Element C_1(){
		return this.C_1.duplicate();
	}
	
	private Element C_2;
	
	public Element C_2(){
		return this.C_2.duplicate();
	}
	private Element C_3;
	
	public Element C_3(){
		return this.C_3.duplicate();
	}
	
	private Element C_4;
	
	public Element C_4(){
		return this.C_4.duplicate();
	}
	
	private Element C_5;
	
	public Element C_5(){
		return this.C_5.duplicate();
	}
	//Lagrange Polynomial for the Node. Only used during encryption
	private transient Polynomial polynomial;
	private transient Element share;
	
	//Only used during audit
	private transient boolean valid;
	
	//only used during decryption
	private transient boolean satisfiable;
	private transient int satisfyNum;
	private transient Element K_1;
	private transient Element K_i_2;
	private transient Element K_i_3;
	private transient Element K_i_4;
	private transient Element decryptNodeResult;
	
	/**
	 * Constructing a leaf node.
	 * @param attribute
	 */
	private LLWCPABEPolicyNode (Pairing pairing, String attribute){
		this.k = 1;
		this.n = 0;
		this.attribute = attribute;
		this.A_i = GroupHash.HashToZp(pairing, attribute.getBytes()).getImmutable();
		this.children = new LLWCPABEPolicyNode[this.n];
		this.polynomial = null;
	}
	
	/**
	 * constructing a threshold node.
	 * @param k threshold.
	 * @param n number of children.
	 */
	private LLWCPABEPolicyNode (int k, int n, LLWCPABEPolicyNode[] children){
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
	
	public LLWCPABEPolicyNode getChildrenAt(int index){
		assert(index < this.n);
		return this.children[index];
	}
	
	public static void sharePolicy(LLWCPABEpp pp, LLWCPABEPolicyNode node, Element e){
		Element indexElement;
		Element shareElement;
//		Element t_i;
		
//		t_i = pp.getPairing().getZr().newRandomElement().getImmutable();
		
		if (node.isLeaf()){
			//Generate ciphertext components
//			node.C_1 = pp.w().powZn(e.duplicate()).mul(pp.v().powZn(t_i.duplicate()));
//			node.C_2 = pp.u().powZn(node.A_i.duplicate()).mul(pp.h()).invert().powZn(t_i.duplicate());
//			node.C_3 = pp.g().powZn(t_i.duplicate());
//			node.C_4 = pp.getPairing().getZr().newZeroElement();
//			node.C_5 = pp.getPairing().getZr().newZeroElement();
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
	
	public static void fillPolicy(LLWCPABEpp pp, LLWCPABEPolicyNode node){
//		Element indexElement;
//		Element shareElement;
		Element t_i;
		
		t_i = pp.getPairing().getZr().newRandomElement().getImmutable();
		
		if (node.isLeaf()){
			//Generate ciphertext components
			node.C_1 = pp.w().powZn(node.share.duplicate()).mul(pp.v().powZn(t_i.duplicate()));
			node.C_2 = pp.u().powZn(node.A_i.duplicate()).mul(pp.h()).invert().powZn(t_i.duplicate());
			node.C_3 = pp.g().powZn(t_i.duplicate());
			node.C_4 = pp.getPairing().getZr().newZeroElement();
			node.C_5 = pp.getPairing().getZr().newZeroElement();
		} else {
			//Note leaf, share the secret
//			node.polynomial = new Polynomial(pp.getPairing(), node.k - 1, e.duplicate());
			for (int i=1; i<= node.n; i++){
//				indexElement = pp.getPairing().getZr().newElement(i).getImmutable();
//				shareElement = node.polynomial.evaluate(indexElement).getImmutable();
				fillPolicy(pp, node.getChildrenAt(i-1));
			}
		}
	}
	
	public static void fillPolicy(LLWCPABEpp pp, LLWCPABEPolicyNode node, LLWCPABEict ict){
//		Element indexElement;
//		Element shareElement;
		
		if (node.isLeaf()){
			//Generate ciphertext components
			Element[] ictComps = ict.ictComps_i();
			node.C_1 = ictComps[3].duplicate();
			node.C_2 = ictComps[4].duplicate();
			node.C_3 = ictComps[5].duplicate();

			node.C_4 = node.share.sub(ictComps[0]);
			node.C_5 = ictComps[2].duplicate().negate().mul(node.A_i.sub(ictComps[1].duplicate()));
		} else {
			//Not leaf, share the secret
//			node.polynomial = new Polynomial(pp.getPairing(), node.k - 1, e.duplicate());
			for (int i=1; i<= node.n; i++){
//				indexElement = pp.getPairing().getZr().newElement(i).getImmutable();
//				shareElement = node.polynomial.evaluate(indexElement).getImmutable();
				fillPolicy(pp, node.getChildrenAt(i-1), ict);
			}
		}
	}
	
	private static void combineCTComps(LLWCPABEPolicyNode node, ArrayList<Element> combinedElement){
		if (node.isLeaf()){
			combinedElement.add(node.C_1.duplicate());
			combinedElement.add(node.C_3.duplicate());
			combinedElement.add(node.C_4.duplicate());
			combinedElement.add(node.C_5.duplicate());
			return;
		} else {
			//Not leaf, traversal the access tree
			for (int i=1; i <= node.n; i++){
				LLWCPABEPolicyNode.combineCTComps(node.getChildrenAt(i - 1), combinedElement);
			}
		}
	}
	
	public static byte[] getVerifyAttribute(LLWCPABEPolicyNode rootNode){
		try {
			ArrayList<Element> combineCTComps = new ArrayList<Element>();
			LLWCPABEPolicyNode.combineCTComps(rootNode, combineCTComps);
			
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
	
	public static long sizeOf(LLWCPABEPolicyNode node){
		if (node.isLeaf()){
			long size = 0;
			//add k
			size += 4;
			//add n
			size += 4;
			
			size += node.A_i.toBytes().length;
			size += node.attribute.getBytes().length;
			size += node.C_1.toBytes().length;
			size += node.C_2.toBytes().length;
			size += node.C_3.toBytes().length;
			size += node.C_4.toBytes().length;
			size += node.C_5.toBytes().length;
			return size;
		} else {
			long size = 0;
			for (int i=0; i < node.n; i++){
				size += sizeOf(node.getChildrenAt(i));
			}
			//add k
			size += 4;
			//add n
			size += 4;
			return size;
		}
	}

	private static void innerAudit(LLWCPABEpp pp, LLWCPABEPolicyNode node){
		node.valid = false;
		if (node.isLeaf()){
			//Do the verification
			if (pp.getPairing().pairing(pp.g(), node.C_2().mul(pp.u().powZn(node.C_5))).mul(pp.getPairing().pairing(node.C_3(), pp.u().powZn(node.A_i).mul(pp.h()))).equals(pp.getPairing().getGT().newOneElement())){
				node.valid = true;
				return;
			} else {
				node.valid = false;
				return;
			}
		} else {
			for (int i=0; i < node.n; i++){
				innerAudit(pp, node.getChildrenAt(i));
			}
			for (int i=0; i < node.n; i++){
				if (!node.getChildrenAt(i).valid){
					node.valid = false;
					return;
				}
			}
			node.valid = true;
			return;
		}
	}
	
	public static boolean audit(LLWCPABEpp pp, LLWCPABEPolicyNode rootNode){
		LLWCPABEPolicyNode.innerAudit(pp, rootNode);
		return rootNode.valid;
	}
	
	private static void checkSatesfiable(LLWCPABEsk sk, LLWCPABEPolicyNode node){
		node.satisfiable = false;
		if (node.isLeaf()){
			for (int i=0; i<sk.numOfAttrs(); i++){
				LLWCPABEsk.LLWCPABEskComps skComps = sk.skComps(i);
				if (node.attribute.equals(skComps.attribute())){
					node.satisfiable = true;
					//fill in the secret key
					node.K_1 = sk.K_1().duplicate().getImmutable();
					node.K_i_2 = skComps.K_2().duplicate().getImmutable();
					node.K_i_3 = skComps.K_3().duplicate().getImmutable();
					node.K_i_4 = skComps.K_4().duplicate().getImmutable();
				}
			}
			return;
		} else {
			//Not leaf, traversal the access tree
			for (int i=0; i < node.n; i++){
				LLWCPABEPolicyNode.checkSatesfiable(sk, node.getChildrenAt(i));
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

	private static void checkSatesfiable(LLWCPABEtk tk, LLWCPABEPolicyNode node){
		node.satisfiable = false;
		if (node.isLeaf()){
			for (int i=0; i<tk.numOfAttrs(); i++){
				LLWCPABEtk.LLWCPABEtkComps tkComps = tk.tkComps(i);
				if (node.attribute.equals(tkComps.attribute())){
					node.satisfiable = true;
					//fill in the secret key
					node.K_1 = tk.K_1().duplicate().getImmutable();
					node.K_i_2 = tkComps.K_2().duplicate().getImmutable();
					node.K_i_3 = tkComps.K_3().duplicate().getImmutable();
					node.K_i_4 = tkComps.K_4().duplicate().getImmutable();
				}
			}
			return;
		} else {
			//Not leaf, traversal the access tree
			for (int i=0; i < node.n; i++){
				LLWCPABEPolicyNode.checkSatesfiable(tk, node.getChildrenAt(i));
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
	
	private static void decryptLeaf(LLWCPABEpp pp, LLWCPABEPolicyNode node){
		assert(node.isLeaf());
		Element temp1 = pp.getPairing().pairing(node.C_1().mul(pp.w().powZn(node.C_4())), node.K_1).getImmutable();
		Element temp2 = pp.getPairing().pairing(node.C_2().mul(pp.u().powZn(node.C_5())), node.K_i_2).getImmutable();
		Element temp3 = pp.getPairing().pairing(node.C_3(), node.K_i_3.mul(pp.u().powZn(node.K_i_4))).getImmutable();
		node.decryptNodeResult = temp1.mul(temp2).mul(temp3).getImmutable();
	}
	
	private static void decryptInternal(LLWCPABEpp pp, LLWCPABEPolicyNode node){
		if (node.isLeaf()){
			LLWCPABEPolicyNode.decryptLeaf(pp, node);
		} else {
			node.decryptNodeResult = pp.getPairing().getGT().newOneElement().getImmutable();
			for (int i=0; i<node.n; i++){
				if (node.getChildrenAt(i).satisfiable){
					LLWCPABEPolicyNode.decryptInternal(pp, node.getChildrenAt(i));
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
	
	public static Element decrypt(LLWCPABEpp pp, LLWCPABEsk sk, LLWCPABEPolicyNode rootNode){
		LLWCPABEPolicyNode.checkSatesfiable(sk, rootNode);
		if (!rootNode.satisfiable){
			return null;
		}
		LLWCPABEPolicyNode.decryptInternal(pp, rootNode);
		return rootNode.decryptNodeResult;
	}
	
	public static Element decrypt(LLWCPABEpp pp, LLWCPABEtk tk, LLWCPABEPolicyNode rootNode){
		LLWCPABEPolicyNode.checkSatesfiable(tk, rootNode);
		if (!rootNode.satisfiable){
			return null;
		}
		LLWCPABEPolicyNode.decryptInternal(pp, rootNode);
		return rootNode.decryptNodeResult;
	}
}
