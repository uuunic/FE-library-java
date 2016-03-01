package cn.edu.buaa.crypto.library.llwcpabe;

import java.text.SimpleDateFormat;
import java.util.Date;

import cn.edu.buaa.crypto.util.Out;
import cn.edu.buaa.crypto.util.StdOut;
import cn.edu.buaa.crypto.util.Timer;

public class TestLLWCPABE {
	private static final String CASE_EXAMPLE_1 = "DOCTOR NURSE 1-2 INSTITUTION 2-2";
	private static final String CASE_EXAMPLE_2 = "TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxx 1-6 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxx 2-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxx 1-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxx 2-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxx 1-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxx 2-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxx 1-3 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxx 2-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxx 1-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxx 4-4 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxxx 1-4 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxxxxxx 2-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxxxxxxx 1-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxxxxxxxx 3-3 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 1-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx TIME_lt_2^32 3-3 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1x TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1 1-5 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxx 3-3 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxx 1-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxx 5-5 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxx 1-4 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxx 3-3 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxx 1-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxx 5-5 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxx 1-3 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxxxx 3-3 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxxxxxx 1-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxxxxxxx 2-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxxxxxxxxx TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxxxxxxxx 1-3 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 2-2 TIME_flexint_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx TIME_ge_2^32 1-3 DOCTOR 3-3";

	private int timeToTest;
	private int numOfTimeTest;
	// Testing Attribute Set with number of attributes from startNum to stopNum
	private int numToTest;
	private int startNum;
	private String[][] AttributeSet;

	private String[] AccessPolicy;

	private double[] setupTime;
	private double[] generalKeyGenTime;
	private double[] offlineKeyGenTime;
	private double[] onlineKeyGenTime;
	private double[] generalEncryptTime;
	private double[] offlineEncryptTime;
	private double[] onlineEncryptTime;
	private double[] generalAuditTime;
	private double[] onlineAuditTime;
	private double[] generalDecryptGeneralTime;
	private double[] onlineDecryptGeneralTime;
	private double[] generalDecryptOnlineTime;
	private double[] onlineDecryptOnlineTime;
//	private double[] outGeneralKeyGenTime;
//	private double[] outOnlineKeyGenTime;
//	private double[] outGeneralTransformGeneralTime;
//	private double[] outOnlineTransformGeneralTime;
//	private double[] outGeneralTransformOnlineTime;
//	private double[] outOnlineTransformOnlineTime;
//	private double[] outDecryptTime;
	
	private double[] example1Time;
	private double[] example2Time;

	public TestLLWCPABE(int timeToTest, int startNum, int numToTest) {
		this.numOfTimeTest = 13;
		this.timeToTest = timeToTest;
		this.numToTest = numToTest;
		this.startNum = startNum;
		this.AttributeSet = new String[numToTest][];
		for (int i = 0; i < numToTest; i++) {
			this.AttributeSet[i] = new String[startNum + i];
		}
		for (int i = 0; i < numToTest; i++) {
			for (int j = 0; j < AttributeSet[i].length; j++) {
				AttributeSet[i][j] = "A_" + j;
			}
		}

		// for (int i=0; i<AttributeSet.length; i++){
		// for (String attr: AttributeSet[i]){
		// StdOut.print(attr + " ");
		// }
		// StdOut.println();
		// }

		this.AccessPolicy = new String[numToTest];
		for (int i = 0; i < numToTest; i++) {
			String tempAccessPolicy = "";
			for (int j = 0; j < AttributeSet[i].length; j++) {
				tempAccessPolicy = tempAccessPolicy.concat(AttributeSet[i][j]
						+ " ");
			}
			tempAccessPolicy = tempAccessPolicy.concat(AttributeSet[i].length
					+ "-" + AttributeSet[i].length);
			this.AccessPolicy[i] = tempAccessPolicy;
		}

		// for (int i=0; i<AccessPolicy.length; i++){
		// StdOut.println(AccessPolicy[i]);
		// }

		this.setupTime = new double[this.numToTest];
		this.generalKeyGenTime = new double[this.numToTest];
		this.offlineKeyGenTime = new double[this.numToTest];
		this.onlineKeyGenTime = new double[this.numToTest];
		this.generalEncryptTime = new double[this.numToTest];
		this.offlineEncryptTime = new double[this.numToTest];
		this.onlineEncryptTime = new double[this.numToTest];
		this.generalAuditTime = new double[this.numToTest];
		this.onlineAuditTime = new double[this.numToTest];
		this.generalDecryptGeneralTime = new double[this.numToTest];
		this.onlineDecryptGeneralTime = new double[this.numToTest];
		this.generalDecryptOnlineTime = new double[this.numToTest];
		this.onlineDecryptOnlineTime = new double[this.numToTest];
//		this.outGeneralKeyGenTime = new double[this.numToTest];
//		this.outOnlineKeyGenTime = new double[this.numToTest];
//		this.outGeneralTransformGeneralTime = new double[this.numToTest];
//		this.outOnlineTransformGeneralTime = new double[this.numToTest];
//		this.outGeneralTransformOnlineTime = new double[this.numToTest];
//		this.outOnlineTransformOnlineTime = new double[this.numToTest];
//		this.outDecryptTime = new double[this.numToTest];
		this.example1Time = new double[this.numOfTimeTest];
		this.example2Time = new double[this.numOfTimeTest];
	}

	private String nowTime() {
		SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");// 设置日期格式
		return df.format(new Date());
	}
	
	private void testExample1OneRound(){
		Timer timer = new Timer(this.numOfTimeTest);
		LLWCPABE llwCPABE = new LLWCPABE();
		// Test Setup
		timer.start(0);
		LLWCPABEmsk msk = llwCPABE.Setup();
		this.example1Time[0] += timer.stop(0);
		LLWCPABEpp pp = llwCPABE.getPublicParameter();
		
		// Test General Encrypt
		LLWCPABEct general_ct = llwCPABE.General_CT_Gen(pp, CASE_EXAMPLE_1);
		timer.start(4);
		llwCPABE.General_Encrypt(pp, general_ct);
		this.example1Time[4] += timer.stop(4);
		
		// Test Offline Encrypt
		timer.start(5);
		LLWCPABEict ict = llwCPABE.Offline_Encrypt(pp, 3);
		this.example1Time[5] += timer.stop(5);

		// Test Online Encrypt
		LLWCPABEct online_ct = llwCPABE.Online_CT_Gen(pp, TestLLWCPABE.CASE_EXAMPLE_1, ict);
		timer.start(6);
		llwCPABE.Online_Encrypt(pp, online_ct, ict);
		this.example1Time[6] += timer.stop(6);
	}
	
	private void testExample2OneRound(){
		Timer timer = new Timer(20);
		LLWCPABE llwCPABE = new LLWCPABE();
		// Test Setup
		timer.start(0);
		LLWCPABEmsk msk = llwCPABE.Setup();
		this.example2Time[0] += timer.stop(0);
		LLWCPABEpp pp = llwCPABE.getPublicParameter();
		
		// Test General Encrypt
		LLWCPABEct general_ct = llwCPABE.General_CT_Gen(pp, TestLLWCPABE.CASE_EXAMPLE_2);
		timer.start(4);
		llwCPABE.General_Encrypt(pp, general_ct);
		this.example2Time[4] += timer.stop(4);
		
		// Test Offline Encrypt
		timer.start(5);
		LLWCPABEict ict = llwCPABE.Offline_Encrypt(pp, 62);
		this.example2Time[5] += timer.stop(5);

		// Test Online Encrypt
		LLWCPABEct online_ct = llwCPABE.Online_CT_Gen(pp, TestLLWCPABE.CASE_EXAMPLE_2, ict);
		timer.start(6);
		llwCPABE.Online_Encrypt(pp, online_ct, ict);
		this.example2Time[6] += timer.stop(6);
	}

	private void testOneRound(int index) {
		assert (index > 0 && index < this.numToTest);

		Timer timer = new Timer(20);
		LLWCPABE llwCPABE = new LLWCPABE();
		// Test Setup
		timer.start(0);
		LLWCPABEmsk msk = llwCPABE.Setup();
		this.setupTime[index] += timer.stop(0);
		LLWCPABEpp pp = llwCPABE.getPublicParameter();

		// Test General KeyGen
		timer.start(1);
		LLWCPABEsk general_sk = llwCPABE.General_KeyGen(msk,
				this.AttributeSet[index]);
		this.generalKeyGenTime[index] += timer.stop(1);

		// Test Offline KeyGen
		timer.start(2);
		LLWCPABEisk isk = llwCPABE.Offline_KeyGen(msk,
				this.AttributeSet[index].length);
		this.offlineKeyGenTime[index] += timer.stop(2);

		// Test Online KeyGen
		timer.start(3);
		LLWCPABEsk online_sk = llwCPABE.Online_KeyGen(this.AttributeSet[index],
				isk);
		this.onlineKeyGenTime[index] += timer.stop(3);

		// Test General Encrypt
		LLWCPABEct general_ct = llwCPABE.General_CT_Gen(pp, this.AccessPolicy[index]);
		timer.start(4);
		llwCPABE.General_Encrypt(pp, general_ct);
		this.generalEncryptTime[index] += timer.stop(4);

		// Test Offline Encrypt
		timer.start(5);
		LLWCPABEict ict = llwCPABE.Offline_Encrypt(pp,
				this.AttributeSet[index].length);
		this.offlineEncryptTime[index] += timer.stop(5);

		// Test Online Encrypt
		LLWCPABEct online_ct = llwCPABE.Online_CT_Gen(pp, this.AccessPolicy[index], ict);
		timer.start(6);
		llwCPABE.Online_Encrypt(pp, online_ct, ict);
		this.onlineEncryptTime[index] += timer.stop(6);

		// Test General Audit
		timer.start(7);
		llwCPABE.Audit(pp, general_ct);
		this.generalAuditTime[index] += timer.stop(7);

		// Test Online Audit
		timer.start(8);
		llwCPABE.Audit(pp, online_ct);
		this.onlineAuditTime[index] += timer.stop(8);

		// Test General Decrypt General
		timer.start(9);
		llwCPABE.Decrypt(pp, general_sk, general_ct);
		this.generalDecryptGeneralTime[index] += timer.stop(9);

		// Test Online Decrypt General
		timer.start(10);
		llwCPABE.Decrypt(pp, online_sk, general_ct);
		this.onlineDecryptGeneralTime[index] += timer.stop(10);

		// Test General Decrypt Online
		timer.start(11);
		llwCPABE.Decrypt(pp, general_sk, online_ct);
		this.generalDecryptOnlineTime[index] += timer.stop(11);

		// Test Online Decrypt Online
		timer.start(12);
		llwCPABE.Decrypt(pp, online_sk, online_ct);
		this.onlineDecryptOnlineTime[index] += timer.stop(12);

//		// Test out General Key Generation Time
//		timer.start(13);
//		LLWCPABEtk general_tk = llwCPABE.Out_KeyGen(pp, general_sk);
//		this.outGeneralKeyGenTime[index] += timer.stop(13);
//
//		// Test out Online Key Generation Time
//		timer.start(14);
//		LLWCPABEtk online_tk = llwCPABE.Out_KeyGen(pp, online_sk);
//		this.outOnlineKeyGenTime[index] += timer.stop(14);
//
//		// Test out General Transform General Time
//		timer.start(15);
//		Element general_general_ct = llwCPABE.Out_Transform(pp, general_tk,
//				general_ct);
//		this.outGeneralTransformGeneralTime[index] += timer.stop(15);
//
//		// Test out Online Transform General Time
//		timer.start(16);
//		Element online_general_ct = llwCPABE.Out_Transform(pp, online_tk,
//				general_ct);
//		this.outOnlineTransformGeneralTime[index] += timer.stop(16);
//
//		// Test out General Transform Online Time
//		timer.start(17);
//		Element general_online_ct = llwCPABE.Out_Transform(pp, general_tk,
//				online_ct);
//		this.outGeneralTransformOnlineTime[index] += timer.stop(17);
//
//		timer.start(18);
//		Element online_online_ct = llwCPABE.Out_Transform(pp, online_tk,
//				online_ct);
//		this.outOnlineTransformOnlineTime[index] += timer.stop(18);
//
//		timer.start(19);
//		llwCPABE.Out_Decrypt(general_general_ct, general_tk.z());
//		this.outDecryptTime[index] += timer.stop(19);
	}

	private void testBenchmark(int index) {
		for (int i = 0; i < this.timeToTest; i++) {
			StdOut.println("Test Round = " + (i+1));
			this.testOneRound(index);
		}
		this.setupTime[index] /= this.timeToTest;
		this.generalKeyGenTime[index] /= this.timeToTest;
		this.offlineKeyGenTime[index] /= this.timeToTest;
		this.onlineKeyGenTime[index] /= this.timeToTest;
		this.generalEncryptTime[index] /= this.timeToTest;
		this.offlineEncryptTime[index] /= this.timeToTest;
		this.onlineEncryptTime[index] /= this.timeToTest;
		this.generalAuditTime[index] /= this.timeToTest;
		this.onlineAuditTime[index] /= this.timeToTest;
		this.generalDecryptGeneralTime[index] /= this.timeToTest;
		this.onlineDecryptGeneralTime[index] /= this.timeToTest;
		this.generalDecryptOnlineTime[index] /= this.timeToTest;
		this.onlineDecryptOnlineTime[index] /= this.timeToTest;
//		this.outGeneralKeyGenTime[index] /= this.timeToTest;
//		this.outOnlineKeyGenTime[index] /= this.timeToTest;
//		this.outGeneralTransformGeneralTime[index] /= this.timeToTest;
//		this.outOnlineTransformGeneralTime[index] /= this.timeToTest;
//		this.outGeneralTransformOnlineTime[index] /= this.timeToTest;
//		this.outOnlineTransformOnlineTime[index] /= this.timeToTest;
//		this.outDecryptTime[index] /= this.timeToTest;
	}
	
	public void testExample1() {
		Out out = new Out("Example1-" + this.nowTime());
		for (int i = 0; i < this.timeToTest; i++) {
			StdOut.println("Test Round = " + (i+1));
			this.testExample1OneRound();
		}
		for (int i=0; i< this.example1Time.length; i++){
			this.example1Time[i] /= this.timeToTest;
		}
		out.printf("%.2f,\t %.2f,\t %.2f,\t %.2f\n",
				this.example1Time[0], this.example1Time[4],
				this.example1Time[5],
				this.example1Time[6]);
	}
	
	public void testExample2() {
		Out out = new Out("Example2-" + this.nowTime());
		for (int i = 0; i < this.timeToTest; i++) {
			StdOut.println("Test Round = " + (i+1));
			this.testExample2OneRound();
		}
		for (int i=0; i< this.example2Time.length; i++){
			this.example2Time[i] /= this.timeToTest;
		}
		out.printf("%.2f,\t %.2f,\t %.2f,\t %.2f\n",
				this.example2Time[0], this.example2Time[4],
				this.example2Time[5],
				this.example2Time[6]);
	}

	public void testBenchmark() {
		Out out = new Out("LLWCPABE-benchmark-" + this.nowTime());
		for (int index = 0; index < this.numToTest; index++) {
			testBenchmark(index);
			out.print(index + ":\t");
			out.printf("%.2f,\t %.2f,\t %.2f,\t %.2f,\t %.2f,\t"
					 + "%.2f,\t %.2f,\t %.2f,\t %.2f,\t %.2f,\t"
					 + "%.2f,\t %.2f,\t %.2f\n",
					this.setupTime[index], 
					this.generalKeyGenTime[index],
					this.offlineKeyGenTime[index],
					this.onlineKeyGenTime[index],
					this.generalEncryptTime[index],
					this.offlineEncryptTime[index],
					this.onlineEncryptTime[index],
					this.generalAuditTime[index], 
					this.onlineAuditTime[index],
					this.generalDecryptGeneralTime[index],
					this.onlineDecryptGeneralTime[index],
					this.generalDecryptOnlineTime[index],
					this.onlineDecryptOnlineTime[index]
//					this.outGeneralKeyGenTime[index],
//					this.outOnlineKeyGenTime[index],
//					this.outGeneralTransformGeneralTime[index],
//					this.outOnlineTransformGeneralTime[index],
//					this.outGeneralTransformOnlineTime[index],
//					this.outOnlineTransformOnlineTime[index],
//					this.outDecryptTime[index]
					);
		}
	}

	public static void main(String[] args) {
		new TestLLWCPABE(1, 50, 1).testBenchmark();
	}
}
