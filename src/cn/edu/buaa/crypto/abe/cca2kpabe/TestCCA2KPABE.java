package cn.edu.buaa.crypto.abe.cca2kpabe;

import cn.edu.buaa.crypto.abe.Type;
import cn.edu.buaa.crypto.util.Out;
import cn.edu.buaa.crypto.util.StdOut;
import cn.edu.buaa.crypto.util.Timer;

public class TestCCA2KPABE {
	private int timeToTest;
	
	private Type type;
	// Testing Attribute Set with number of attributes from startNum to stopNum
	private int numToTest;
	private String[][] AttributeSet;

	private String[] AccessPolicy;

	private double[] setupTime;
	private double[] keyGenTime;
	private double[] encryptTime;
	private double[] decryptTime;

	public TestCCA2KPABE(Type type, int timeToTest, int startNum, int numToTest) {
		this.type = type;
		this.timeToTest = timeToTest;
		this.numToTest = numToTest;
		this.AttributeSet = new String[numToTest][];
		for (int i = 0; i < numToTest; i++) {
			this.AttributeSet[i] = new String[startNum + i];
		}
		for (int i = 0; i < numToTest; i++) {
			for (int j = 0; j < AttributeSet[i].length; j++) {
				AttributeSet[i][j] = "A_" + j;
			}
		}

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

		this.setupTime = new double[this.numToTest];
		this.keyGenTime = new double[this.numToTest];
		this.encryptTime = new double[this.numToTest];
		this.decryptTime = new double[this.numToTest];
	}

	private void testOneRound(int index) {
		assert (index > 0 && index < this.numToTest);

		Timer timer = new Timer(20);
		CCA2KPABE cca2KPABE = new CCA2KPABE();
		// Test Setup
		timer.start(0);
		CCA2KPABEmsk msk = cca2KPABE.Setup(type);
		this.setupTime[index] += timer.stop(0);
		CCA2KPABEpp pp = cca2KPABE.getPublicParameter();

		// Test General KeyGen
		CCA2KPABEsk secret_key = cca2KPABE.KeyGen_LSSS(pp, msk, this.AccessPolicy[index]);
		timer.start(1);
		cca2KPABE.KeyGen(pp, msk, secret_key);
		this.keyGenTime[index] += timer.stop(1);

		// Test Encrypt
		timer.start(4);
		CCA2KPABEct ciphertext = cca2KPABE.Encrypt(pp, this.AttributeSet[index]);
		this.encryptTime[index] += timer.stop(4);

		// Test Decrypt
		timer.start(9);
		cca2KPABE.Decrypt(pp, secret_key, ciphertext);
		this.decryptTime[index] += timer.stop(9);
	}

	private void testBenchmark(int index) {
		for (int i = 0; i < this.timeToTest; i++) {
			StdOut.println("Test Round = " + (i+1));
			this.testOneRound(index);
		}
		this.setupTime[index] /= this.timeToTest;
		this.keyGenTime[index] /= this.timeToTest;
		this.encryptTime[index] /= this.timeToTest;
		this.decryptTime[index] /= this.timeToTest;
	}

	public void testBenchmark() {
		String testType = "";
		if (this.type == Type.CPA){
			testType = "CPA-secure_";
		} else {
			testType = "CCA2-secure_";
		}
		Out out = new Out("CCA2KPABE_" + testType + Timer.nowTime());
		for (int index = 0; index < this.numToTest; index++) {
			testBenchmark(index);
			out.print(index + ":\t");
			out.printf("%.2f,\t %.2f,\t %.2f,\t %.2f\n",
					this.setupTime[index], 
					this.keyGenTime[index],
					this.encryptTime[index],
					this.decryptTime[index]
					);
		}
	}

	public static void main(String[] args) {
		new TestCCA2KPABE(Type.CPA, 1, 1, 10).testBenchmark();
//		new TestCCA2KPABE(Type.CCA2, 1, 1, 20).testBenchmark();
	}
}
