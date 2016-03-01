package cn.edu.buaa.crypto.hibbe.sscpa;

import cn.edu.buaa.crypto.util.Out;
import cn.edu.buaa.crypto.util.StdOut;
import cn.edu.buaa.crypto.util.Timer;

public class Test_SS_CPA_HIBBE {
	private final int max_role;
	private final int max_depth;
	
	private double setupTime[];
	
	private double KeyGenTime[];
	private double DelegateTime[];
	private double EncryptTime[];
	private double DecryptTime[];
	
	private String [][] role_vector;
	private final String [][] role_vector_set;
	
	private SS_CPA_HIBBE hibbe;
	private HIBBEpp pp;
	private HIBBEmsk msk;
	
	private HIBBEsk[] sk;
	private HIBBEct[] ct;
	
	public Test_SS_CPA_HIBBE(int D, int N){
		this.max_role = N;
		this.max_depth = D;
		
		this.hibbe = new SS_CPA_HIBBE();
		this.msk = this.hibbe.Setup(this.max_depth, this.max_role);
		this.pp = hibbe.getPublicParameter();
		RoleManager roleManager = this.pp.get_role_manager();
		
		//Add roles in the role manager
		for (int i=0; i<this.max_role; i++){
			roleManager.addRole("ID_" + (i+1));
		}
		
		//Create the role vector
		this.role_vector = new String[this.max_depth][];
		for (int i=0; i<this.role_vector.length; i++){
			this.role_vector[i] = new String[i+1];
		}
		
		for (int i=0; i<this.max_depth; i++){
			for (int j=i; j<this.max_depth; j++){
				this.role_vector[j][i] = "ID_" + (i+1);
			}
		}
		
		//TODO remove it
		//Show the created role vector
		for (int i=0; i<this.role_vector.length; i++){
			for (int j=0; j<this.role_vector[i].length; j++){
				StdOut.print(this.role_vector[i][j] + " ");
			}
			StdOut.println();
		}
		
		//Create the role vector set
		this.role_vector_set = new String[this.max_role][];
		for (int i=0; i<this.role_vector_set.length; i++){
			this.role_vector_set[i] = new String[i+1];
		}
		
		for (int i=0; i<this.max_role; i++){
			for (int j=i; j<this.max_role; j++){
				this.role_vector_set[j][i] = "ID_" + (i+1);
			}
		}
		
		//TODO remove it
		//Show the created role vector set
		for (int i=0; i<this.role_vector_set.length; i++){
			for (int j=0; j<this.role_vector_set[i].length; j++){
				StdOut.print(this.role_vector_set[i][j] + " ");
			}
			StdOut.println();
		}
		
		this.setupTime = new double[this.max_role];
		this.KeyGenTime = new double[this.max_depth];
		this.DelegateTime = new double[this.max_depth];
		this.EncryptTime = new double[this.max_role];
		this.DecryptTime = new double[this.max_role];
		
		//Create ac for EHRdec
		this.sk = new HIBBEsk[this.max_depth];
		this.ct = new HIBBEct[this.max_role];
	}
	
	private void test_setup_one_round(){
		Timer timer = new Timer(this.max_role);
		
		for (int i=0; i<this.max_role; i++){
			timer.start(i);
			SS_CPA_HIBBE setupRBAC = new SS_CPA_HIBBE();
			setupRBAC.Setup(max_depth, (i+1));
			this.setupTime[i] += timer.stop(i);
		}
	}
	
	private void test_ac_gen_one_round(){
		Timer timer = new Timer(this.max_depth);
		
		//Access Credential Generation and Delegation Time
		HIBBEisk isk = hibbe.IKeyGen();
		for (int i=0; i<this.max_depth; i++){
			timer.start(i);
			this.sk[i] = hibbe.KeyGen(msk, this.role_vector[i], isk);
//			this.sk[i] = hibbe.KeyGen(msk, this.role_vector[i]);
			this.KeyGenTime[i] += timer.stop(i);
		}
		
		//Access Credential Delegate Time
		HIBBEsk delegate_sk = hibbe.KeyGen(msk, this.role_vector[0], isk);
//		HIBBEsk delegate_sk = hibbe.KeyGen(msk, this.role_vector[0]);
		for (int i=1; i<this.max_depth; i++){
			timer.start(i);
			delegate_sk = hibbe.Delegate(delegate_sk, this.role_vector[i][i], isk);
//			delegate_sk = hibbe.Delegate(delegate_sk, this.role_vector[i][i]);
			this.DelegateTime[i] += timer.stop(i);
		}
	}
	
	private void test_enc_one_round(){
		Timer timer = new Timer(this.max_role);
		
		//Encryption Time
		for (int i=0; i<this.max_role; i++){
			timer.start(i);
			this.ct[i] = hibbe.Encrypt(pp, this.role_vector_set[i]);
			this.EncryptTime[i] += timer.stop(i);
		}
	}
	
	private void test_dec_one_round(){
		Timer timer = new Timer(this.max_role);
		//Decapsulation Time
		for (int j=0; j<this.max_role; j++){
			timer.start(j);
			hibbe.Decrypt(pp, ct[j], sk[0]);
			this.DecryptTime[j] += timer.stop(j);
		}
	}
	
	public void testBenchmark(int numToTest){
		for (int i=0; i<numToTest; i++){
			StdOut.println("Test Round = " + (i+1));
//			this.test_setup_one_round();
			this.test_ac_gen_one_round();
			this.test_enc_one_round();
			this.test_dec_one_round();
		}
		
		Out out = new Out("Full-secure-HIBBE-benchmark-" + Timer.nowTime());
		
//		out.println("Setup Time");
//		for (int i=0; i<this.setupTime.length; i++){
//			setupTime[i] /= numToTest;
//			out.printf("%.2f\t", setupTime[i]);
//		}
//		out.println();
		
		out.println("Secret Key Generation Time");
		for (int i=0; i<this.KeyGenTime.length; i++){
			KeyGenTime[i] /= numToTest;
			out.printf("%.2f\t", KeyGenTime[i]);
		}
		out.println();
		
		out.println("Secret Key Delegation Time");
		for (int i=0; i<this.DelegateTime.length; i++){
			DelegateTime[i] /= numToTest;
			out.printf("%.2f\t", DelegateTime[i]);
		}
		out.println();
		
		out.println("Encryption Time");
		for (int i=0; i<this.EncryptTime.length; i++){
			EncryptTime[i] /= numToTest;
			out.printf("%.2f\t", EncryptTime[i]);
		}
		out.println();
		
		out.println("Decryption Time");
		out.println("EHR Decapsulation Time for Role Vector Length = " + 1);
		for (int j=0; j<this.DecryptTime.length; j++){
			DecryptTime[j] /= numToTest;
			out.printf("%.2f\t", DecryptTime[j]);
		}
		out.println();
	}
	
	public static void main(String[] args){
		new Test_SS_CPA_HIBBE(10, 50).testBenchmark(100);
	}
}
