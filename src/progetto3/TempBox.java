package progetto3;

public class TempBox {
	private byte[] h;
	private boolean lr;
	
	public TempBox(byte[] h, boolean lr) {
		this.h = h;
		this.lr = lr;
	}
	public byte[] getH() {
		return h;
	}
	public void setH(byte[] h) {
		this.h = h;
	}
	public boolean isLr() {
		return lr;
	}
	public void setLr(boolean lr) {
		this.lr = lr;
	}
	
	
}
