package cn.edu.buaa.crypto.algs;

import cn.edu.buaa.crypto.base.ParameterGenerator;
import cn.edu.buaa.crypto.test.FuncTest;
import cn.edu.buaa.crypto.util.StdOut;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Polynomial implements FuncTest {
	private final Pairing pairing;
	private final int degree;
	private final Element[] coef;

	/**
	 * Lagrange polynomial construction
	 * 
	 * @param pairing
	 *            Pairing Parameters
	 * @param degree
	 *            degree of the polynomial
	 * @param zeroValue
	 *            value of poly(0)
	 */
	public Polynomial(Pairing pairing, int degree, Element zeroValue) {
		this.pairing = pairing;
		this.degree = degree;
		this.coef = new Element[this.degree + 1];
		this.coef[0] = zeroValue.duplicate().getImmutable();
		for (int i = 1; i < coef.length; i++) {
			this.coef[i] = this.pairing.getZr().newRandomElement()
					.getImmutable();
		}
	}

	/**
	 * Evaluate the value of poly(x)
	 * 
	 * @param x
	 * @return poly(x)
	 */
	public Element evaluate(Element x) {
		Element result = pairing.getZr().newZeroElement().getImmutable();
		Element temp = pairing.getZr().newOneElement().getImmutable();

		for (int i = 0; i < this.degree + 1; i++) {
			for (int j = 0; j < i; j++) {
				temp = temp.mul(x).getImmutable();
			}
			temp = temp.mul(coef[i]).getImmutable();
			result = result.add(temp).getImmutable();
			temp = pairing.getZr().newOneElement().getImmutable();
		}
		return result;
	}

	/**
	 * Calculate Lagrange coefficient
	 * 
	 * @param set
	 *            the index set S
	 * @param index
	 *            the given index
	 * @return Lagrange coefficient \dalta_(i, S)(0)
	 */
	public static Element calCoef(Pairing pairing, int[] set, int index) {
		Element[] elementSet = new Element[set.length];
		for (int i = 0; i < set.length; i++) {
			elementSet[i] = pairing.getZr().newElement(set[i]).getImmutable();
		}
		Element elementIndex = pairing.getZr().newElement(index).getImmutable();
		Element result = pairing.getZr().newOneElement().getImmutable();

		for (int i = 0; i < set.length; i++) {
			if (set[i] == index) {
				continue;
			}
			Element member = pairing.getZr().newZeroElement()
					.sub(elementSet[i]).getImmutable();
			Element denominator = elementIndex.sub(elementSet[i])
					.getImmutable();
			result = result.mul(member).mul(denominator.invert());
		}
		return result;
	}

	@Override
	public void FunctionTest() {
		Pairing pairing = PairingFactory
				.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);
		Element zeroValue = pairing.getZr().newRandomElement().getImmutable();
		StdOut.println("Poly(0) = " + zeroValue);

		// Test polynomial evaluation
		Polynomial polynomial = new Polynomial(pairing, 4, zeroValue);
		Element value1 = pairing.getZr().newOneElement().getImmutable();
		Element value2 = pairing.getZr().newOneElement().add(value1)
				.getImmutable();
		Element value3 = pairing.getZr().newOneElement().add(value2)
				.getImmutable();
		Element value4 = pairing.getZr().newOneElement().add(value3)
				.getImmutable();
		Element value5 = pairing.getZr().newOneElement().add(value4)
				.getImmutable();
		Element value6 = pairing.getZr().newOneElement().add(value5)
				.getImmutable();
		Element value7 = pairing.getZr().newOneElement().add(value6)
				.getImmutable();
		Element value8 = pairing.getZr().newOneElement().add(value7)
				.getImmutable();
		Element value9 = pairing.getZr().newOneElement().add(value8)
				.getImmutable();
		StdOut.println("Poly(1) = " + polynomial.evaluate(value1));
		StdOut.println("Poly(2) = " + polynomial.evaluate(value2));
		StdOut.println("Poly(3) = " + polynomial.evaluate(value3));
		StdOut.println("Poly(4) = " + polynomial.evaluate(value4));
		StdOut.println("Poly(5) = " + polynomial.evaluate(value5));
		StdOut.println("Poly(6) = " + polynomial.evaluate(value6));
		StdOut.println("Poly(7) = " + polynomial.evaluate(value7));
		StdOut.println("Poly(8) = " + polynomial.evaluate(value8));
		StdOut.println("Poly(9) = " + polynomial.evaluate(value9));

		// Test zeroValue reconstruction
		int[] set = { 1, 2, 4, 6, 8 };
		Element reValue1 = Polynomial.calCoef(pairing, set, 1).mul(
				polynomial.evaluate(value1));
		Element reValue2 = Polynomial.calCoef(pairing, set, 2).mul(
				polynomial.evaluate(value2));
		Element reValue3 = Polynomial.calCoef(pairing, set, 4).mul(
				polynomial.evaluate(value4));
		Element reValue4 = Polynomial.calCoef(pairing, set, 6).mul(
				polynomial.evaluate(value6));
		Element reValue5 = Polynomial.calCoef(pairing, set, 8).mul(
				polynomial.evaluate(value8));
		Element reZeroValue = reValue1.add(reValue2).add(reValue3)
				.add(reValue4).add(reValue5);
		StdOut.println("Recst = " + reZeroValue);
		assert (zeroValue.equals(reZeroValue));
	}
}
