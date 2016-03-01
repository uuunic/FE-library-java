package cn.edu.buaa.crypto.abe.cca2cpabe;

import cn.edu.buaa.crypto.abe.Type;
import cn.edu.buaa.crypto.util.Out;
import cn.edu.buaa.crypto.util.StdOut;
import cn.edu.buaa.crypto.util.Timer;

public class TestCCA2CPABE {
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

	public TestCCA2CPABE(Type type, int timeToTest, int startNum, int numToTest) {
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
		CCA2CPABE cca2CPABE = new CCA2CPABE();
		// Test Setup
		timer.start(0);
		CCA2CPABEmsk msk = cca2CPABE.Setup(type);
		this.setupTime[index] += timer.stop(0);
		CCA2CPABEpp pp = cca2CPABE.getPublicParameter();

		// Test General KeyGen
		timer.start(1);
		CCA2CPABEsk secret_key = cca2CPABE.KeyGen(msk, this.AttributeSet[index]);
		this.keyGenTime[index] += timer.stop(1);

		// Test Encrypt
		CCA2CPABEct ciphertext = cca2CPABE.Encrypt_LSSS(pp, this.AccessPolicy[index]);
		timer.start(4);
		cca2CPABE.Encrypt(pp, ciphertext);
		this.encryptTime[index] += timer.stop(4);

		// Test Decrypt
		timer.start(9);
		cca2CPABE.Decrypt(pp, secret_key, ciphertext);
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
		Out out = new Out("CCA2CPABE_" + testType + Timer.nowTime());
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
		new TestCCA2CPABE(Type.CPA, 1, 1, 20).testBenchmark();
		new TestCCA2CPABE(Type.CCA2, 1, 1, 20).testBenchmark();
	}
}
