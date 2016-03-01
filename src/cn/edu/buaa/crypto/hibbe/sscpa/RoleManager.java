package cn.edu.buaa.crypto.hibbe.sscpa;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;


public class RoleManager {
	private final int max_depth;
	private final int max_role;
	private final HIBBEpp pp;
	private ArrayList<String> roleSet;
	private ArrayList<Element> roleHashSet;
	private final ArrayList<Element> u_pow_role;
	
	public RoleManager(HIBBEpp pp, int D, int N){
		this.pp = pp;
		this.max_depth = D;
		this.max_role = N;
		this.roleSet = new ArrayList<String>(max_role);
		this.roleHashSet = new ArrayList<Element>(max_role);
		this.u_pow_role = new ArrayList<Element>(max_role);
	}
	
	public void addRoleVector(String[] roleVector){
		//Make sure that the length of Role Vector less than the Max Depth
		assert(roleVector.length < this.max_depth);
		int numOfAdd = 0;
		for (int i=0; i<roleVector.length; i++){
			if (!roleSet.contains(roleVector[i])){
				numOfAdd++;
			}
		}
		
		//Make sure that the number of added role plus the added roles less than the max number of role
		assert(numOfAdd + roleSet.size() < this.max_role);
		for (int i=0; i<roleVector.length; i++){
			this.addRole(roleVector[i]);
		}
		return;
	}
	
	public void addRoleSet(String[] addRoleSet){
		int numOfAdd = 0;
		for (int i=0; i<addRoleSet.length; i++){
			if (!roleSet.contains(addRoleSet[i])){
				numOfAdd++;
			}
		}
		
		//Make sure that the number of added role plus the added roles less than the max number of role
		assert(numOfAdd + roleSet.size() < this.max_role);
		for (int i=0; i<addRoleSet.length; i++){
			this.addRole(addRoleSet[i]);
		}
		return;
	}
	
	public void addRole(String role){
		assert(roleSet.contains(role));
		roleSet.add(role);
		roleHashSet.add(hash_id(role).getImmutable());
		int index = this.indexOf(role);
		u_pow_role.add(pp.get_u(index).powZn(this.roleHashSet.get(index)).getImmutable());
		return;
	}
	
	public int indexOf(String role){
		return this.roleSet.indexOf(role);
	}
	
	public Element hashOf(String role){
		int index = this.indexOf(role);
		if (index == -1){
			return null;
		}else{
			return this.roleHashSet.get(index);
		}
	}
	
	public Element uPowerOf(String role){
		int index = this.indexOf(role);
		if (index == -1){
			return null;
		}else{
			return this.u_pow_role.get(index);
		}
	}
	
	private Element hash_id(String id){
		byte[] byte_identity = id.getBytes();
		Element hash = pp.get_pairing().getZr().newElement().setFromHash(byte_identity, 0, byte_identity.length);
		return hash;
	}
}
