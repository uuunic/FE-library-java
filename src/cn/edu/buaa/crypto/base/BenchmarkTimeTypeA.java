package cn.edu.buaa.crypto.base;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import cn.edu.buaa.crypto.test.BenchmarkTest;
import cn.edu.buaa.crypto.util.In;
import cn.edu.buaa.crypto.util.Out;
import cn.edu.buaa.crypto.util.StdOut;
import cn.edu.buaa.crypto.util.Timer;

public class BenchmarkTimeTypeA implements BenchmarkTest {
	private final Pairing pairing;
	private Element G_1;
	private Element G_1_p;
	private Element G_2;
	private Element G_2_p;
	private Element Z_r;
	private Element Z_r_p;
	private Element G_T;
	private Element G_T_p;
	private double[] time;
	private int timeToTest;
	
	public BenchmarkTimeTypeA(int timeToTest){
		this.timeToTest = timeToTest;
		this.pairing = PairingFactory.getPairing(ParameterGenerator.PATH_TYPE_A_PARAMETER);
		this.time = new double[9];
	}
	
	private void testOneRound(){
		this.G_1 = pairing.getG1().newRandomElement().getImmutable();
		this.G_2 = pairing.getG2().newRandomElement().getImmutable();
		this.Z_r = pairing.getZr().newRandomElement().getImmutable();
		this.G_T = pairing.getGT().newRandomElement().getImmutable();
		
		this.G_1_p = pairing.getG1().newRandomElement().getImmutable();
		this.G_2_p = pairing.getG2().newRandomElement().getImmutable();
		this.Z_r_p = pairing.getZr().newRandomElement().getImmutable();
		this.G_T_p = pairing.getGT().newRandomElement().getImmutable();
		Timer timer = new Timer(9);
		
		//Operations in G_1
		StdOut.println("Test Operations in G_1");
		timer.start(0);
		this.G_1.duplicate().mul(this.G_1_p.duplicate());
		this.time[0] += timer.stop(0);
		timer.start(1);
		this.G_1.duplicate().powZn(this.Z_r.duplicate());
		this.time[1] += timer.stop(1);
		
		//Operations in G_2
		StdOut.println("Test Operations in G_2");
		timer.start(2);
		this.G_2.duplicate().mul(this.G_2_p.duplicate());
		this.time[2] += timer.stop(2);
		timer.start(3);
		this.G_2.duplicate().powZn(this.Z_r.duplicate());
		this.time[3] += timer.stop(3);
		
		//Operations in G_T
		StdOut.println("Test Operations in G_T");
		timer.start(4);
		this.G_T.duplicate().mul(this.G_T_p.duplicate());
		this.time[4] += timer.stop(4);
		timer.start(5);
		this.G_T.duplicate().powZn(this.Z_r.duplicate());
		this.time[5] += timer.stop(5);
		
		//Operations in Pairing
		StdOut.println("Test Operations in Pairing");
		timer.start(6);
		pairing.pairing(this.G_1.duplicate(), this.G_2.duplicate());
		this.time[6] += timer.stop(6);
		
		//Operations in Z_r
		StdOut.println("Test Operations in Z_r");
		timer.start(7);
		this.Z_r.duplicate().add(this.Z_r_p.duplicate());
		this.time[7] += timer.stop(7);
		timer.start(8);
		this.Z_r.duplicate().mul(this.Z_r_p).duplicate();
		this.time[8] += timer.stop(8);
	}
	
	public void testBenchmark(){
		Out out = new Out("Benchmark-" + Timer.nowTime());
		for (int i = 0; i < this.timeToTest; i++) {
			StdOut.println("Test Round = " + (i+1));
			this.testOneRound();
		}
		for (int i=0; i< this.time.length; i++){
			this.time[i] /= this.timeToTest;
		}
		out.println("Benchmark Test with Properties:");
		In inTypeA = new In(ParameterGenerator.PATH_TYPE_A_PARAMETER);
		out.println(inTypeA.readAll());
		out.printf("Mul. in G_1 = %.5fms\n", this.time[0]);
		out.printf("Exp. in G_1 = %.5fms\n", this.time[1]);
		out.printf("Mul. in G_2 = %.5fms\n", this.time[2]);
		out.printf("Exp. in G_2 = %.5fms\n", this.time[3]);
		out.printf("Mul. in G_T = %.5fms\n", this.time[4]);
		out.printf("Exp. in G_T = %.5fms\n", this.time[5]);
		out.printf("Pair in G_T = %.5fms\n", this.time[6]);
		out.printf("Add. in Z_r = %.5fms\n", this.time[7]);
		out.printf("Mul. in Z_r = %.5fms\n", this.time[8]);
	}

	@Override
	public void BenchmarkTime(int round) {
		new BenchmarkTimeTypeA(round).testBenchmark();
	}
}
