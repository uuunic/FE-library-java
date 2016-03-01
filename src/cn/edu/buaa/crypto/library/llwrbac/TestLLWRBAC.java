package cn.edu.buaa.crypto.library.llwrbac;

import cn.edu.buaa.crypto.util.Out;
import cn.edu.buaa.crypto.util.StdOut;
import cn.edu.buaa.crypto.util.Timer;

public class TestLLWRBAC {
	private final int max_role;
	private final int max_depth;
	
	private double setupTime[];
	
	private double acGenPTime;
	private double acGenTime[];
	private double acDelegateTime[];
	private double EHREncTime[];
	private double EHRAuditTime[];
	
	private double EHRDecPTime[];
	private double EHRDecTime[][];
	
	private String[] patient_role_vector;
	private String [][] role_vector;
	private final String [][] role_vector_set;
	
	private LLWRBAC llwRBAC;
	private LLWRBACpp pp;
	private LLWRBACmsk msk;
	
	private LLWRBACac ac_patient;
	private LLWRBACac[] ac;
	private LLWRBACct[] ct;
	
	public TestLLWRBAC(int D, int N){
		this.max_role = N;
		this.max_depth = D;
		
		this.llwRBAC = new LLWRBAC();
		this.msk = this.llwRBAC.SetupCCASecure(this.max_depth, this.max_role);
		this.pp = llwRBAC.getPublicParameter();
		RoleManager roleManager = this.pp.get_role_manager();
		
		//Create the patient role vector
		this.patient_role_vector = new String[1];
		this.patient_role_vector[0] = "Role_1";
		
		//Add roles in the role manager
		for (int i=0; i<this.max_role; i++){
			roleManager.addRole("Role_" + (i+1));
		}
		
		//Create the role vector
		this.role_vector = new String[this.max_depth][];
		for (int i=0; i<this.role_vector.length; i++){
			this.role_vector[i] = new String[i+1];
		}
		
		for (int i=0; i<this.max_depth; i++){
			for (int j=i; j<this.max_depth; j++){
				this.role_vector[j][i] = "Role_" + (i+1);
			}
		}
		
//		//Show the created role vector
//		for (int i=0; i<this.role_vector.length; i++){
//			for (int j=0; j<this.role_vector[i].length; j++){
//				StdOut.print(this.role_vector[i][j] + " ");
//			}
//			StdOut.println();
//		}
		
		//Create the role vector set
		this.role_vector_set = new String[this.max_role][];
		for (int i=0; i<this.role_vector_set.length; i++){
			this.role_vector_set[i] = new String[i+1];
		}
		
		for (int i=0; i<this.max_role; i++){
			for (int j=i; j<this.max_role; j++){
				this.role_vector_set[j][i] = "Role_" + (i+1);
			}
		}
		
		//Show the created role vector set
		for (int i=0; i<this.role_vector_set.length; i++){
			for (int j=0; j<this.role_vector_set[i].length; j++){
				StdOut.print(this.role_vector_set[i][j] + " ");
			}
			StdOut.println();
		}
		
		this.setupTime = new double[this.max_role];
		this.acGenTime = new double[this.max_depth];
		this.acDelegateTime = new double[this.max_depth];
		this.EHREncTime = new double[this.max_role];
		this.EHRAuditTime = new double[this.max_role];
		this.EHRDecPTime = new double[this.max_role];
		this.EHRDecTime = new double[this.max_depth][this.max_role];
		
		//Create ac for EHRdec
		this.ac = new LLWRBACac[this.max_depth];
		this.ct = new LLWRBACct[this.max_role];
	}
	
	private void test_setup_one_round(){
		Timer timer = new Timer(this.max_role);
		
		for (int i=0; i<this.max_role; i++){
			timer.start(i);
			LLWRBAC setupRBAC = new LLWRBAC();
			setupRBAC.SetupCCASecure(max_depth, (i+1));
			this.setupTime[i] += timer.stop(i);
		}
	}
	
	private void test_ac_gen_p_one_round(){
		Timer timer = new Timer();
		LLWRBACiac iac = llwRBAC.IACGen();
		timer.start(0);
		this.ac_patient = llwRBAC.ACGen(msk, patient_role_vector, iac);
		this.acGenPTime += timer.stop(0);
	}
	
	private void test_ac_gen_one_round(){
		Timer timer = new Timer(this.max_depth);
		
		//Access Credential Generation and Delegation Time
		LLWRBACiac iac = llwRBAC.IACGen();
		for (int i=0; i<this.max_depth; i++){
			timer.start(i);
			this.ac[i] = llwRBAC.ACGen(msk, this.role_vector[i], iac);
			this.acGenTime[i] += timer.stop(i);
		}
		
		//Access Credential Delegate Time
		LLWRBACac delegate_ac = llwRBAC.ACGen(msk, this.role_vector[0], iac);
		for (int i=1; i<this.max_depth; i++){
			timer.start(i);
			delegate_ac = llwRBAC.ACDelegate(delegate_ac, this.role_vector[i][i], iac);
			this.acDelegateTime[i] += timer.stop(i);
		}
	}
	
	private void test_enc_one_round(){
		Timer timer = new Timer(this.max_role);
		
		//Encapsulation Time
		for (int i=0; i<this.max_role; i++){
			timer.start(i);
			this.ct[i] = llwRBAC.EHREnc(pp, this.role_vector_set[i]);
			this.EHREncTime[i] += timer.stop(i);
		}
		
		//Audit Time
		for (int i=0; i<this.max_role; i++){
			timer.start(i);
			llwRBAC.Audit(pp, this.ct[i]);
			this.EHRAuditTime[i] += timer.stop(i);
		}
	}
	
	private void test_dec_p_one_round(){
		Timer timer = new Timer();
		for (int i=0; i<this.max_role; i++){
			timer.start(i);
			llwRBAC.EHRDec(pp, ct[i], ac_patient);
			this.EHRDecPTime[i] += timer.stop(i);
		}
	}
	
	private void test_dec_one_round(){
		Timer timer = new Timer(this.max_role);
		//Decapsulation Time
		for (int i=0; i<this.max_depth; i++){
			for (int j=i; j<this.max_role; j++){
				timer.start(j);
				llwRBAC.EHRDec(pp, ct[j], ac[i]);
				this.EHRDecTime[i][j] += timer.stop(j);
			}
		}
	}
	
	public void testBenchmark(int numToTest){
		for (int i=0; i<numToTest; i++){
			StdOut.println("Test Round = " + (i+1));
			this.test_setup_one_round();
			this.test_ac_gen_p_one_round();
			this.test_ac_gen_one_round();
			this.test_enc_one_round();
			this.test_dec_p_one_round();
			this.test_dec_one_round();
		}
		
		Out out = new Out("LLWRBAC-benchmark-" + Timer.nowTime());
		
		out.println("Setup Time");
		for (int i=0; i<this.setupTime.length; i++){
			setupTime[i] /= numToTest;
			out.printf("%.2f\t", setupTime[i]);
		}
		out.println();
		
		out.println("Patient Access Credential Generation Time");
		this.acGenPTime /= numToTest;
		out.printf("%.2f\t", acGenPTime);
		out.println();
		
		out.println("Access Credential Generation Time");
		for (int i=0; i<this.acGenTime.length; i++){
			acGenTime[i] /= numToTest;
			out.printf("%.2f\t", acGenTime[i]);
		}
		out.println();
		
		out.println("Access Credential Delegation Time");
		for (int i=0; i<this.acDelegateTime.length; i++){
			acDelegateTime[i] /= numToTest;
			out.printf("%.2f\t", acDelegateTime[i]);
		}
		out.println();
		
		out.println("EHR Encapsulation Time");
		for (int i=0; i<this.EHREncTime.length; i++){
			EHREncTime[i] /= numToTest;
			out.printf("%.2f\t", EHREncTime[i]);
		}
		out.println();
		
		out.println("EHR Audit Time");
		for (int i=0; i<this.EHRAuditTime.length; i++){
			EHRAuditTime[i] /= numToTest;
			out.printf("%.2f\t", EHRAuditTime[i]);
		}
		out.println();
		
		out.println("EHR Patient Decapsulation Time");
		for (int i=0; i<this.EHRDecPTime.length; i++){
			EHRDecPTime[i] /= numToTest;
			out.printf("%.2f\t", EHRDecPTime[i]);
		}
		out.println();
		
		for (int i=0; i<this.EHRDecTime.length; i++){
			out.println("EHR Decapsulation Time for Role Vector Length = " + (i+1));
			for (int j=i; j<this.EHRDecTime[i].length; j++){
				EHRDecTime[i][j] /= numToTest;
				out.printf("%.2f\t", EHRDecTime[i][j]);
			}
			out.println();
		}
	}
	
	public static void main(String[] args){
		new TestLLWRBAC(10, 100).testBenchmark(100);
	}
}
