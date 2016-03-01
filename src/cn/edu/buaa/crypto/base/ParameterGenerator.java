package cn.edu.buaa.crypto.base;

import cn.edu.buaa.crypto.util.In;
import cn.edu.buaa.crypto.util.Out;
import cn.edu.buaa.crypto.util.StdOut;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.e.TypeECurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFCurveGenerator;

public class ParameterGenerator {
	public static final String PATH_TYPE_A_PARAMETER = "params/a.properties";
	public static final String PATH_TYPE_A1_PARAMETER = "params/a1.properties";
	public static final String PATH_TYPE_D159_PARAMETER = "params/d159.properties";
	public static final String PATH_TYPE_D201_PARAMETER = "params/d201.properties";
	public static final String PATH_TYPE_D224_PARAMETER = "params/d224.properties";
	public static final String PATH_TYPE_E_PARAMETER = "params/e.properties";
	public static final String PATH_TYPE_F_PARAMETER = "params/f.properties";
	public static final String PATH_TYPE_G149_PARAMETER = "params/g149.properties";

	/**
	 * Generate a valid Type A Parameters. It is symmetric.
	 * 
	 * @param rBits
	 *            Order of Zp, 160 typically.
	 * @param qBits
	 *            Order of G1, G2 and GT, 512 typically.
	 * @return Generated Type A Parameters
	 */
	public static PairingParameters GenerateTypeAParameter(int rBits, int qBits) {
		TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
		PairingParameters typeAParams = pg.generate();
		Out out = new Out(PATH_TYPE_A_PARAMETER);
		StdOut.println("Type A Parameter Generated, rBits = " + rBits
				+ ", qBits = " + qBits);
		out.println(typeAParams);
		return typeAParams;
	}

	/**
	 * Generate a valid Type A1 Parameters. It is symmetric.
	 * 
	 * @param numPrime
	 *            number of factors for the composite order
	 * @param qBits
	 *            order of each factors, 517 typically.
	 * @return Generated Type A1 Parameters
	 */
	public static PairingParameters GenerateTypeA1Parameter(int numPrime,
			int qBits) {
		TypeA1CurveGenerator pg = new TypeA1CurveGenerator(numPrime, qBits);
		PairingParameters typeA1Params = pg.generate();
		Out out = new Out(PATH_TYPE_A1_PARAMETER);
		StdOut.println("Type A1 Parameter Generated with " + numPrime
				+ " primes, qBits = " + qBits);
		out.println(typeA1Params);
		return typeA1Params;
	}

	/**
	 * Generate a valid Type E Parameters. As q is typically 1024 bits, group
	 * elements take a lot of space to represent. Moreover, many optimizations
	 * do not apply to this type, resulting in a slower pairing.
	 * 
	 * @param rBits
	 *            Order of Zp, 160 typically.
	 * @param qBits
	 *            Order of G1, G2 and GT, 1024 typically.
	 * @return Generated Type E Parameters
	 */
	public static PairingParameters GenerateTypeEParameter(int rBits, int qBits) {
		TypeECurveGenerator pg = new TypeECurveGenerator(rBits, qBits);
		PairingParameters typeEParams = pg.generate();
		Out out = new Out(PATH_TYPE_E_PARAMETER);
		StdOut.println("Type E Parameter Generated, rBits = " + rBits
				+ ", qBits = " + qBits);
		out.println(typeEParams);
		return typeEParams;
	}

	/**
	 * Generate a valid Type F Parameters. Only 160 bits are needed to represent
	 * elements of one group, and 320 bits for the other.
	 * 
	 * @param rBits
	 *            Order of Zp, G1, G2 and GT, 160 typically.
	 * @return Generated Type F Parameters
	 */
	public static PairingParameters GenerateTypeFParameter(int rBits) {
		TypeFCurveGenerator pg = new TypeFCurveGenerator(rBits);
		PairingParameters typeFParams = pg.generate();
		Out out = new Out(PATH_TYPE_F_PARAMETER);
		StdOut.println("Type F Parameter Generated, rBits = " + rBits);
		out.println(typeFParams);
		return typeFParams;
	}
	
	public static void main(String[] args){
		//Test Type A Parameter Generator
//		PairingParameters typeAParams = ParameterGenerator.GenerateTypeAParameter(160, 512);
//		StdOut.println(typeAParams);
//		In inTypeA = new In(ParameterGenerator.PATH_TYPE_A_PARAMETER);
//		StdOut.println(inTypeA.readAll());
		
		//Test Type A1 Parameter Generator
		PairingParameters typeA1Params = ParameterGenerator.GenerateTypeA1Parameter(3, 512);
		StdOut.println(typeA1Params);
		In inTypeA1 = new In(ParameterGenerator.PATH_TYPE_A1_PARAMETER);
		StdOut.println(inTypeA1.readAll());
//
//		//Test Type E Parameter Generator
//		PairingParameters typeEParams = ParameterGenerator.GenerateTypeEParameter(160, 512);
//		StdOut.println(typeEParams);
//		In inTypeE = new In(ParameterGenerator.PATH_TYPE_E_PARAMETER);
//		StdOut.println(inTypeE.readAll());
//		
//		//Test Type F Parameter Generator
//		PairingParameters typeFParams = ParameterGenerator.GenerateTypeFParameter(160);
//		StdOut.println(typeFParams);
//		In inTypeF = new In(ParameterGenerator.PATH_TYPE_F_PARAMETER);		
//		StdOut.println(inTypeF.readAll());
	}
}
