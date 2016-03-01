package cn.edu.buaa.crypto.library.asgka;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class ASGKAGroupParameter {
	private final Pairing pairing;
	private final int n;
	private final Element g;
	private final Element[] array_h;
	private Element[][] array_sigma;
	private Element[] array_R;
	private Element[] array_A;
	
	
	public ASGKAGroupParameter(Pairing pairing, final int n){
		this.pairing = pairing;
		this.n = n;
		
		//Generate g
		this.g = pairing.getG1().newRandomElement().getImmutable();
		
		//Generate h_1, \cdots h_n \in \mathbb{G}
		this.array_h = new Element[n];
		for (int i=0; i<this.array_h.length; i++){
			this.array_h[i] = pairing.getG1().newRandomElement().getImmutable();
		}
		
		//Init \{sigma_{i, j}, R_i, A_i\}
		this.array_sigma = new Element[this.n][this.n];
		this.array_R = new Element[this.n];
		this.array_A = new Element[this.n];
	}
	
	public Element array_h(int i){
		assert(isValidIndex(i));
		return this.array_h[i].duplicate();
	}
	
	public void setSigma(final int i, Element X_i, Element r_i){
		assert(isValidIndex(i));
		this.array_R[i] = this.g.powZn(r_i.duplicate().negate()).getImmutable();
		this.array_A[i] = pairing.pairing(X_i.duplicate(), this.g).getImmutable();
		for (int j=0; j < this.n; j++){
			if (i == j){
				continue;
			} else {
				this.array_sigma[i][j] = X_i.duplicate().mul(this.array_h(j).powZn(r_i.duplicate())).getImmutable();
			}
		}
	}
	
	public Element sigma_i_j(int i, int j){
		assert(isValidIndex(i) && isValidIndex(j) && i != j);
		return this.array_sigma[i][j].duplicate();
	}
	
	public Element R_i(int i){
		assert (isValidIndex(i));
		return this.array_R[i].duplicate();
	}
	
	public Element A_i(int i){
		assert (isValidIndex(i));
		return this.array_A[i].duplicate();
	}
	
	public Pairing pairing(){
		return this.pairing;
	}
	
	public int n(){
		return this.n;
	}
	
	public Element g(){
		return this.g.duplicate();
	}
	
	private boolean isValidIndex(int i){
		return (i >=0 && i<this.n);
	}
}
