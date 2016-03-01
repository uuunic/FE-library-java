package cn.edu.buaa.crypto.library.llwcpabe;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cn.edu.buaa.crypto.algs.GeneralHash;
import cn.edu.buaa.crypto.algs.LLWChameleonHash;
import cn.edu.buaa.crypto.algs.GeneralHash.HashMode;
import cn.edu.buaa.crypto.algs.SymmetricBlockEnc;
import cn.edu.buaa.crypto.algs.ChameleonHash.HashData;
import cn.edu.buaa.crypto.algs.SymmetricBlockEnc.Mode;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.util.StdOut;

public class LLWCPABE {
	public static final int P = 10;
//	public static final int DEFAULT_R_BITS = 160;
//	public static final int DEFAULT_Q_BITS = 512;
	
	private final Pairing pairing;
	private LLWCPABEpp pp;
	
	/**
	 * Construct an instance of LLWCPABE scheme
	 */
	public LLWCPABE(){
//		ParameterGenerator.GenerateTypeAParameter(DEFAULT_R_BITS, DEFAULT_Q_BITS);
		this.pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);  
	}
	
	/**
	 * Obtain the public parameter from the LLWCAPBE instance
	 * @return public parameter pp
	 */
	public LLWCPABEpp getPublicParameter(){
		return this.pp;
	}
	
	/**
	 * Setup algorithm, setting up the LLWCPABE scheme
	 * @return master secret key msk
	 */
	public LLWCPABEmsk Setup(){
		StdOut.println("Setup: System Setup.");
		Element alpha = pairing.getZr().newRandomElement().getImmutable();
		LLWCPABEmsk msk = new LLWCPABEmsk(alpha);
		this.pp = new LLWCPABEpp(pairing, alpha);
		return msk;
	}
	
	/**
	 * General Key Generation Algorithm
	 * @param msk master secret key
	 * @param attrs attribute set for the key
	 * @return secret key associated with attribute set
	 */
	public LLWCPABEsk General_KeyGen(LLWCPABEmsk msk, String[] attrs){
		String combinedAttrs = new String("");
		for (String attr: attrs){
			combinedAttrs = combinedAttrs.concat(attr + " ");
		}
		StdOut.println("General.KeyGen: General Generate secret key with attributes = " + combinedAttrs);
		return new LLWCPABEsk(pairing, pp, msk, attrs);
	}
	
	/**
	 * Offline Key Generation Algorithm
	 * @param msk master secret key
	 * @param P the number of intermediate secret key components need to generate
	 * @return intermediate secret key isk
	 */
	public LLWCPABEisk Offline_KeyGen(LLWCPABEmsk msk, int P){
		StdOut.println("Offline.KeyGen: Offline Generate intermediate secret key with P = " + P);
		return new LLWCPABEisk(pairing, pp, msk, P);
	}
	
	/**
	 * Online Key Generation Algorithm
	 * @param attrs attribute set
	 * @param isk intermediate secret key
	 * @return secret key associated with attribute set
	 */
	public LLWCPABEsk Online_KeyGen(String[] attrs, LLWCPABEisk isk){
		String combinedAttrs = new String("");
		for (String attr: attrs){
			combinedAttrs = combinedAttrs.concat(attr + " ");
		}
		StdOut.println("Online.KeyGen: Oneline Generate secret key with attributes " + combinedAttrs);
		return new LLWCPABEsk(pairing, pp, attrs, isk);
	}
	
	public LLWCPABEct General_CT_Gen(LLWCPABEpp pp, String policy){
		StdOut.println("General.Encrypt: General Encrypt");
		LLWCPABEct ct = new LLWCPABEct(pp, policy);
		return ct;
	}
	
	public LLWCPABEct Online_CT_Gen(LLWCPABEpp pp, String policy, LLWCPABEict ict){
		StdOut.println("Online.Encrypt: Online Encrypt");
		LLWCPABEct ct = new LLWCPABEct(pp, policy, ict);
		return ct;
	}
	
	/**
	 * General Encrypt Algorithm for Encrypting byte[]
	 * @param pp public parameter
	 * @param policy access policy
	 */
	public void General_Encrypt(LLWCPABEpp pp, LLWCPABEct ct){
		ct.generalEncrypt(pp);
	}
	
	/**
	 * General Encrypt Algorithm for Encrypting a file
	 * @param pp public parameter
	 * @param policy
	 * @param fileIn
	 * @param fileOut
	 */
	public void General_Encrypt(LLWCPABEpp pp, LLWCPABEct ct, File fileIn, File fileOut){
		try {
			ct.generalEncrypt(pp);
			FileInputStream in = new FileInputStream(fileIn);
			FileOutputStream out = new FileOutputStream(fileOut);
			SymmetricBlockEnc.enc_AES(Mode.CBC, GeneralHash.Hash(HashMode.SHA256, ct.key().toBytes()), SymmetricBlockEnc.InitVector, in, out);
			in.close();
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new RuntimeException();
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
	
	/**
	 * Offline Encrypt Algorithm 
	 * @param pp public parameter
	 * @param P the number of ciphertext components need to generate
	 * @return intermediate ciphertext ict
	 */
	public LLWCPABEict Offline_Encrypt(LLWCPABEpp pp, int P){
		StdOut.println("Offline.Encrypt: Offline Encrypt with P = " + P);
		return new LLWCPABEict(pairing, pp, P);
	}
	
	/**
	 * Online Encrypt Algorithm for Encrypting byte[]
	 * @param pp public parameter
	 * @param policy access policy
	 * @param ict intermediate ciphertext
	 */
	public void Online_Encrypt(LLWCPABEpp pp, LLWCPABEct ct, LLWCPABEict ict){
		ct.onlineEncrypt(pp, ict);
	}
	
	/**
	 * Online Encrypt Algorithm for Encrypting a file
	 * @param pp public parameter
	 * @param policy access policy
	 * @param ict intermediate ciphertext
	 * @param fileIn file to be encrypted
	 * @param fileOut encrypted file
	 */
	public void Online_Encrypt(LLWCPABEpp pp, LLWCPABEct ct, LLWCPABEict ict, File fileIn, File fileOut){
		try{
			ct.onlineEncrypt(pp, ict);
			FileInputStream in = new FileInputStream(fileIn);
			FileOutputStream out = new FileOutputStream(fileOut);
			SymmetricBlockEnc.enc_AES(Mode.CBC, GeneralHash.Hash(HashMode.SHA256, ct.key().toBytes()), SymmetricBlockEnc.InitVector, in, out);
			in.close();
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new RuntimeException();
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
	
	/**
	 * Audit Algorithm
	 * @param pp public parameter
	 * @param ct ciphertex to be audited
	 * @return true if valid, false if invalid
	 */
	public boolean Audit(LLWCPABEpp pp, LLWCPABEct ct){
		LLWChameleonHash chameleonHash = new LLWChameleonHash(pairing);
		HashData hashData = chameleonHash.setHashData(LLWCPABEPolicyNode.getVerifyAttribute(ct.getPolicyTree()), ct.rChameleonHash());
		Element verificationAttribute = chameleonHash.hashVerification(ct.gChameleonHash(), ct.hChameleonHash(), hashData).getImmutable();
		//Test Verification Attribute
		if (!pairing.pairing(pp.g(), ct.C_0_2()).mul(pairing.pairing(ct.C_0_3(), pp.u().powZn(verificationAttribute).mul(pp.h()))).equals(pairing.getGT().newOneElement())){
			StdOut.println("Audit: Audit Ciphertext result = Invalid...");
			return false;
		} else {
			boolean auditResult = LLWCPABEPolicyNode.audit(pp, ct.getPolicyTree());
			if (!auditResult){
				StdOut.println("Audit: Audit Ciphertext result = Invalid...");
			} else {
				StdOut.println("Audit: Audit Ciphertext result = Valid!");
			}
			return auditResult;
		}
	}
	
	/**
	 * Decrypt Algorithm for recovering data byte[]
	 * @param pp public parameter
	 * @param sk secret key
	 * @param ct ciphetext
	 * @return encapsuated key
	 */
	public Element Decrypt(LLWCPABEpp pp, LLWCPABEsk sk, LLWCPABEct ct){
		Element temp0 = pp.getPairing().pairing(ct.C_0(), sk.K_0()).getImmutable();
		Element temp1 = LLWCPABEPolicyNode.decrypt(pp, sk, ct.getPolicyTree());
		if (temp1 == null){
			StdOut.println("Do not satisfy the access policy, decrypt fail...");
			return null;
		}
		Element key = temp0.mul(temp1.invert()).getImmutable();
		StdOut.println("LLWCPABE Decrypt: Encapsulated key = " + key);
		return key;
//		byte[] ciphertext = Hex.decode(ct.encapsulated());
//		byte[] plaintext = SymmetricEnc.dec_AES_CBC(GeneralHash.SHA256(key.toBytes()), SymmetricEnc.InitVector, ciphertext);
//		StdOut.println(new String(plaintext));
//		return plaintext;
	}
	
	/**
	 * Decrypt Algorithm for recovering file
	 * @param pp public parameter
	 * @param sk secret key
	 * @param ct ciphertext
	 * @param fileIn encrypted file
	 * @param fileOut decrypted file
	 */
	public void Decrypt(LLWCPABEpp pp, LLWCPABEsk sk, LLWCPABEct ct, File fileIn, File fileOut){
		Element temp0 = pp.getPairing().pairing(ct.C_0(), sk.K_0()).getImmutable();
		Element temp1 = LLWCPABEPolicyNode.decrypt(pp, sk, ct.getPolicyTree());
		if (temp1 == null){
			StdOut.println("Do not satisfy the access policy, decrypt fail...");
			return;
		}
		Element key = temp0.mul(temp1.invert()).getImmutable();
		try{
			StdOut.println("LLWCPABE Decrypt: Encapsulated key = " + key);
			FileInputStream in = new FileInputStream(fileIn);
			FileOutputStream out = new FileOutputStream(fileOut);
			SymmetricBlockEnc.dec_AES(Mode.CBC, GeneralHash.Hash(HashMode.SHA256, ct.key().toBytes()), SymmetricBlockEnc.InitVector, in, out);
			in.close();
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new RuntimeException();
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
	
	public LLWCPABEtk Out_KeyGen(LLWCPABEpp pp, LLWCPABEsk sk){
		StdOut.println("Out.KeyGen: Out Key Generation with numOfAttrs = " + sk.numOfAttrs());
		return new LLWCPABEtk(pp, sk);
	}
	
	public Element Out_Transform(LLWCPABEpp pp, LLWCPABEtk tk, LLWCPABEct ct){
		StdOut.println("Out.Transform: Transforming Ciphertext for numOfAttrs = " + tk.numOfAttrs());
		Element temp0 = pp.getPairing().pairing(ct.C_0(), tk.K_0()).getImmutable();
		Element temp1 = LLWCPABEPolicyNode.decrypt(pp, tk, ct.getPolicyTree());
		if (temp1 == null){
			StdOut.println("Do not satisfy the access policy, decrypt fail...");
			return null;
		}
		Element key = temp0.mul(temp1.invert()).getImmutable();
//		StdOut.println("LLWCPABE Decrypt: Encapsulated key = " + key);
		return key;
	}
	
	public Element Out_Decrypt(Element transformTK, Element z){
		StdOut.println("Out.Decrypt: Out Decryption for Recover Key");
		Element key = transformTK.powZn(z.duplicate()).getImmutable();
		StdOut.println("LLWCPABE Out_Decrypt: Encapsulated key = " + key);
		return key;
	}
	
	public void Out_Decrypt(Element transformTK, Element z, File fileIn, File fileOut){
		StdOut.println("Out.Decrypt: Out Decryption for Decrypting File");
		Element key = transformTK.powZn(z.duplicate()).getImmutable();
		try{
			StdOut.println("LLWCPABE Decrypt: Encapsulated key = " + key);
			FileInputStream in = new FileInputStream(fileIn);
			FileOutputStream out = new FileOutputStream(fileOut);
			SymmetricBlockEnc.dec_AES(Mode.CBC, GeneralHash.Hash(HashMode.SHA256, key.toBytes()), SymmetricBlockEnc.InitVector, in, out);
			in.close();
			out.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new RuntimeException();
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException();
		}
	}
}
