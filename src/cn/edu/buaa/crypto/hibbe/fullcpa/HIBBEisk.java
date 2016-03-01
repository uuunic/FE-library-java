package cn.edu.buaa.crypto.hibbe.fullcpa;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

public class HIBBEisk {
	private final Element g;
	private final Element h;
	private final Element[] u;
	private Element random_3;
	
	public HIBBEisk(HIBBEpp pp){
		Element generator = pp.get_pairing().getG1().newRandomElement().getImmutable();
		this.u = new Element[pp.get_u_length()];
		Element r = pp.get_pairing().getZr().newRandomElement().getImmutable();
		for (int i=0; i<pp.get_u_length(); i++){
			this.random_3 = ElementUtils.getGenerator(pp.get_pairing(), generator, pp.getCurveParameters(), 2, 3).getImmutable();
			this.u[i] = pp.get_u(i).powZn(r).mul(random_3).getImmutable();
		}
		this.random_3 = ElementUtils.getGenerator(pp.get_pairing(), generator, pp.getCurveParameters(), 2, 3).getImmutable();
		this.g = pp.get_g().duplicate().powZn(r).mul(random_3).getImmutable();
		this.random_3 = ElementUtils.getGenerator(pp.get_pairing(), generator, pp.getCurveParameters(), 2, 3).getImmutable();
		this.h = pp.get_h().duplicate().powZn(r).mul(random_3).getImmutable();
	}
	
	public Element get_g(){
		return this.g.duplicate();
	}
	
	public Element get_h(){
		return this.h.duplicate();
	}
	
	public Element get_u(int index){
		return this.u[index].duplicate();
	}
}
