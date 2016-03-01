package cn.edu.buaa.crypto.hibbe.sscca;

import it.unisa.dia.gas.jpbc.Element;

public class HIBBEsk {
	private final String[] roleVector;
	private Element a_0;
	private Element a_1;
	private Element[] b;
	
	public HIBBEsk(HIBBEpp pp, HIBBEmsk msk, String[] roleVector){
		int index[] = new int[roleVector.length];
		Element r = pp.get_pairing().getZr().newRandomElement().getImmutable();
		this.roleVector = roleVector;
		//compute a_0
		this.a_0 = pp.get_g_3().duplicate();
		for (int i=0; i<roleVector.length; i++){
			index[i] = pp.get_role_manager().indexOf(roleVector[i]);
			this.a_0 = this.a_0.mul(pp.get_u(index[i]).powZn(pp.get_role_manager().hashOf(roleVector[i])));
		}
		this.a_0 = this.a_0.powZn(r);
		this.a_0 = this.a_0.mul(msk.get_g_2_alpha()).getImmutable();
		//compute a_1
		this.a_1 = pp.get_g().powZn(r).getImmutable();
		//compute b
		this.b = new Element[pp.get_max_role()+1];
		for (int i=0; i<pp.get_max_role(); i++){
			boolean isInIndex = false;
			for (int j=0; j<index.length; j++){
				if (i == index[j]){
					isInIndex = true;
				}
			}
			if (isInIndex){
				continue;
			}else{
				this.b[i] = pp.get_u(i).powZn(r).getImmutable();
			}
		}
		this.b[pp.get_max_role()] = pp.get_u(pp.get_max_role()).powZn(r).getImmutable();
	}
	
	public HIBBEsk(HIBBEpp pp, HIBBEmsk msk, String[] roleVector, HIBBEisk iac){
		int index[] = new int[roleVector.length];
		this.roleVector = roleVector;
		//compute a_0
		this.a_0 = iac.get_g_3();
		for (int i=0; i<this.roleVector.length; i++){
			index[i] = pp.get_role_manager().indexOf(roleVector[i]);
			this.a_0 = this.a_0.mul(iac.get_u(i).powZn(pp.get_role_manager().hashOf(roleVector[i])));
		}
		this.a_0 = this.a_0.mul(msk.get_g_2_alpha()).getImmutable();
		//compute a_1
		this.a_1 = iac.get_g().getImmutable();
		//compute b
		this.b = new Element[pp.get_max_role()+1];
		for (int i=0; i<pp.get_max_role(); i++){
			boolean isInIndex = false;
			for (int j=0; j<index.length; j++){
				if (i == index[j]){
					isInIndex = true;
				}
			}
			if (isInIndex){
				continue;
			}else{
				this.b[i] = iac.get_u(i).getImmutable();
			}
		}
		this.b[pp.get_max_role()] =iac.get_u(pp.get_max_role()).getImmutable();
	}
	
	public HIBBEsk(HIBBEpp pp, HIBBEsk ac, String role){
		this.roleVector = new String[ac.get_role_vector().length + 1];
		System.arraycopy(ac.get_role_vector(), 0, this.roleVector, 0, ac.get_role_vector().length);
		this.roleVector[ac.get_role_vector().length] = role;
		int index[] = new int[this.roleVector.length];
		Element r = pp.get_pairing().getZr().newRandomElement().getImmutable();
		
		//compute a_0
		this.a_0 = pp.get_g_3().duplicate();
		for (int i=0; i<this.roleVector.length; i++){
			index[i] = pp.get_role_manager().indexOf(this.roleVector[i]);
			this.a_0 = this.a_0.mul(pp.get_u(index[i]).powZn(pp.get_role_manager().hashOf(this.roleVector[i])));
		}
		this.a_0 = this.a_0.powZn(r);
		this.a_0 = this.a_0.mul(ac.get_a_0());
		this.a_0 = this.a_0.mul(ac.get_b(pp.get_role_manager().indexOf(role)).powZn(pp.get_role_manager().hashOf(role))).getImmutable();
		//compute a_1
		this.a_1 = ac.get_a_1().mul(pp.get_g().powZn(r)).getImmutable();
		//compute b
		this.b = new Element[pp.get_max_role() + 1];
		for (int i=0; i<pp.get_max_role(); i++){
			boolean isInIndex = false;
			for (int j=0; j<index.length; j++){
				if (i == index[j]){
					isInIndex = true;
				}
			}
			if (isInIndex){
				continue;
			}else{
				this.b[i] = pp.get_u(i).powZn(r).mul(ac.get_b(i)).getImmutable();
			}
		}
		this.b[pp.get_max_role()] = pp.get_u(pp.get_max_role()).powZn(r).mul(ac.get_b(pp.get_max_role())).getImmutable();
	}
	
	public HIBBEsk(HIBBEpp pp, HIBBEsk ac, String role, HIBBEisk iac){
		this.roleVector = new String[ac.get_role_vector().length + 1];
		System.arraycopy(ac.get_role_vector(), 0, this.roleVector, 0, ac.get_role_vector().length);
		this.roleVector[ac.get_role_vector().length] = role;
		int index[] = new int[this.roleVector.length];
		
		//compute a_0
		this.a_0 = iac.get_g_3().duplicate();
		for (int i=0; i<this.roleVector.length; i++){
			index[i] = pp.get_role_manager().indexOf(this.roleVector[i]);
			this.a_0 = this.a_0.mul(iac.get_u(i).powZn(pp.get_role_manager().hashOf(this.roleVector[i])));
		}
		this.a_0 = this.a_0.mul(ac.get_a_0());
		this.a_0 = this.a_0.mul(ac.get_b(pp.get_role_manager().indexOf(role)).powZn(pp.get_role_manager().hashOf(role))).getImmutable();
		//compute a_1
		this.a_1 = ac.get_a_1().mul(iac.get_g()).getImmutable();
		//compute b
		this.b = new Element[pp.get_max_role()+1];
		for (int i=0; i<pp.get_max_role(); i++){
			boolean isInIndex = false;
			for (int j=0; j<index.length; j++){
				if (i == index[j]){
					isInIndex = true;
				}
			}
			if (isInIndex){
				continue;
			}else{
				this.b[i] = iac.get_u(i).mul(ac.get_b(i)).getImmutable();
			}
		}
		this.b[pp.get_max_role()] = iac.get_u(pp.get_max_role()).mul(ac.get_b(pp.get_max_role())).getImmutable();
	}
	
	public Element get_a_0(){
		return this.a_0.duplicate();
	}
	
	public Element get_a_1(){
		return this.a_1.duplicate();
	}
	
	public Element get_b(int index){
		return this.b[index];
	}
	
	public String[] get_role_vector(){
		return this.roleVector;
	}
}
