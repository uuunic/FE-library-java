package cn.edu.buaa.crypto.algs;

import cn.edu.buaa.crypto.algs.GeneralHash.HashMode;
import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.test.FuncTest;
import cn.edu.buaa.crypto.util.StdOut;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class GroupHash implements FuncTest {
	/**
	 * Hash arbitrary byte[] to element in Zp
	 * 
	 * @param Pairing
	 *            Paring Object
	 * @param data
	 *            Hashed Data
	 * @return Hashed Value in Zp
	 */
	public static Element HashToZp(Pairing pairing, byte[] data) {
		// assert that data is not a null object
		assert (data != null);
		// assert that data length is not zero
		assert (data.length != 0);
		byte[] sha256 = GeneralHash.Hash(HashMode.SHA256, data);
		Element hash = pairing.getZr().newElement()
				.setFromHash(sha256, 0, sha256.length);
		return hash;
	}

	/**
	 * Hash arbitrary byte[] to element in G1
	 * 
	 * @param Pairing
	 *            Paring Object
	 * @param data
	 *            Hashed Data
	 * @return Hashed Value in G1
	 */
	public static Element HashToG1(Pairing pairing, byte[] data) {
		// assert that data is not a null object
		assert (data != null);
		// assert that data length is not zero
		assert (data.length != 0);
		byte[] sha256 = GeneralHash.Hash(HashMode.SHA256, data);
		Element hash = pairing.getG1().newElement()
				.setFromHash(sha256, 0, sha256.length);
		return hash;
	}

	/**
	 * Hash arbitrary byte[] to element in G2
	 * 
	 * @param Pairing
	 *            Paring Object
	 * @param data
	 *            Hashed Data
	 * @return Hashed Value in G2
	 */
	public static Element HashToG2(Pairing pairing, byte[] data) {
		// assert that data is not a null object
		assert (data != null);
		// assert that data length is not zero
		assert (data.length != 0);
		byte[] sha256 = GeneralHash.Hash(HashMode.SHA256, data);
		Element hash = pairing.getG2().newElement()
				.setFromHash(sha256, 0, sha256.length);
		return hash;
	}

	/**
	 * Hash arbitrary byte[] to element in GT
	 * 
	 * @param Pairing
	 *            Paring Object
	 * @param data
	 *            Hashed Data
	 * @return Hashed Value in GT
	 */
	public static Element HashToGT(Pairing pairing, byte[] data) {
		// assert that data is not a null object
		assert (data != null);
		// assert that data length is not zero
		assert (data.length != 0);
		byte[] sha256 = GeneralHash.Hash(HashMode.SHA256, data);
		Element hash = pairing.getGT().newElement()
				.setFromHash(sha256, 0, sha256.length);
		return hash;
	}

	@Override
	public void FunctionTest() {
		Pairing pairing = PairingFactory
				.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);
		String message1 = "TestGroupHash-1";
		String message2 = "TestGroupHash-2";

		// Test HashToZp
		Element byteZp = GroupHash.HashToZp(pairing, message1.getBytes());
		StdOut.println("HashToZp, message = " + message1);
		StdOut.println("Result = " + byteZp);
		// Hash result for the same value should be equal
		Element byteZp_1 = GroupHash.HashToZp(pairing, message1.getBytes());
		StdOut.println("HashToZp, message = " + message1);
		StdOut.println("Result = " + byteZp_1);
		assert (byteZp.equals(byteZp_1));
		// Hash result for different values should be distinct
		Element byteZp_2 = GroupHash.HashToZp(pairing, message2.getBytes());
		StdOut.println("HashToZp, message = " + message2);
		StdOut.println("Result = " + byteZp_2);
		assert (!byteZp.equals(byteZp_2));

		// Test HashToG1
		Element byteG1 = GroupHash.HashToG1(pairing, message1.getBytes());
		StdOut.println("HashToG1, message = " + message1);
		StdOut.println("Result = " + byteG1);
		// Hash result for the same value should be equal
		Element byteG1_1 = GroupHash.HashToG1(pairing, message1.getBytes());
		StdOut.println("HashToG1, message = " + message1);
		StdOut.println("Result = " + byteG1_1);
		assert (byteG1.equals(byteG1_1));
		// Hash result for different values should be distinct
		Element byteG1_2 = GroupHash.HashToG1(pairing, message2.getBytes());
		StdOut.println("HashToG1, message = " + message2);
		StdOut.println("Result = " + byteG1_2);
		assert (!byteG1.equals(byteG1_2));

		// Test HashToG2
		Element byteG2 = GroupHash.HashToG2(pairing, message1.getBytes());
		StdOut.println("HashToG2, message = " + message1);
		StdOut.println("Result = " + byteG2);
		// Hash result for the same value should be equal
		Element byteG2_1 = GroupHash.HashToG2(pairing, message1.getBytes());
		StdOut.println("HashToG2, message = " + message1);
		StdOut.println("Result = " + byteG2_1);
		assert (byteG2.equals(byteG2_1));
		// Hash result for different values should be distinct
		Element byteG2_2 = GroupHash.HashToG2(pairing, message2.getBytes());
		StdOut.println("HashToG2, message = " + message2);
		StdOut.println("Result = " + byteG2_2);
		assert (!byteG2.equals(byteG2_2));

		// Test HashToGT
		Element byteGT = GroupHash.HashToGT(pairing, message1.getBytes());
		StdOut.println("HashToGT, message = " + message1);
		StdOut.println("Result = " + byteGT);
		// Hash result for the same value should be equal
		Element byteGT_1 = GroupHash.HashToGT(pairing, message1.getBytes());
		StdOut.println("HashToGT, message = " + message1);
		StdOut.println("Result = " + byteGT_1);
		assert (byteGT.equals(byteGT_1));
		// Hash result for different values should be distinct
		Element byteGT_2 = GroupHash.HashToGT(pairing, message2.getBytes());
		StdOut.println("HashToGT, message = " + message2);
		StdOut.println("Result = " + byteGT_2);
		assert (!byteGT.equals(byteGT_2));
	}
}
