package cn.edu.buaa.crypto.hibbe.fullcpa;

import cn.edu.buaa.crypto.base.ParameterGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

public class HIBBEpp {
	private final Pairing pairing;
	private final PairingParameters curveParameters;
	
	private final int max_depth;
	private final int max_role;
	
	private final Element g;
	private final Element h;
	private final Element[] u;
	private final Element X_3;
	private final Element e_alpha;
	
	private final RoleManager roleManager;
	
	public HIBBEpp(int D, int N, Element alpha){
		this.pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A1_PARAMETER);
		this.curveParameters = PairingFactory.getPairingParameters(ParameterGenerator.PATH_TYPE_A1_PARAMETER);
		this.max_depth = D;
		this.max_role = N;
		
		Element generator = pairing.getG1().newRandomElement().getImmutable();
		this.g = ElementUtils.getGenerator(pairing, generator, curveParameters, 0, 3).getImmutable();
		this.h = ElementUtils.getGenerator(pairing, generator, curveParameters, 0, 3).getImmutable();
		
		this.u = new Element[max_role];
		for (int i=0; i<max_role; i++){
			this.u[i] = ElementUtils.getGenerator(pairing, generator, curveParameters, 0, 3).getImmutable();
		}
		
		this.X_3 = ElementUtils.getGenerator(pairing, generator, curveParameters, 2, 3).getImmutable();
		this.e_alpha = pairing.pairing(this.g, this.g).powZn(alpha).getImmutable();
		this.roleManager = new RoleManager(this, D, N);
	}
	
	public Element get_u(int index){
		return this.u[index].duplicate();
	}
	
	public int get_u_length(){
		return this.u.length;
	}
	
	public Element get_g(){
		return this.g.duplicate();
	}
	
	public Element get_h(){
		return this.h.duplicate();
	}
	
	public Element get_X_3(){
		return this.X_3.duplicate();
	}
	
	public Element get_e_alpha(){
		return this.e_alpha.duplicate();
	}
	
	public int get_max_depth(){
		return this.max_depth;
	}
	
	public int get_max_role(){
		return this.max_role;
	}
	
	public Pairing get_pairing(){
		return this.pairing;
	}
	
	public RoleManager get_role_manager(){
		return this.roleManager;
	}
	
	public PairingParameters getCurveParameters(){
		return this.curveParameters;
	}
}
