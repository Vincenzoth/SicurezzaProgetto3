package progetto3;

public class LinkedInfoUnit {
	private byte[] h;
	private boolean lr;
	
	public LinkedInfoUnit(byte[] h, boolean lr) {
		this.h = h;
		this.lr = lr; // TRUE = RIGHT
	}
	public byte[] getH() {
		return h;
	}
	public void setH(byte[] h) {
		this.h = h;
	}
	public boolean isR() {
		return lr;
	}
	public void setLr(boolean lr) {
		this.lr = lr;
	}
}
