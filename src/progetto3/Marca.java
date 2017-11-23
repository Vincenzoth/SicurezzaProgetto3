package progetto3;

import java.security.Timestamp;

public class Marca {
	private String idUser;
	private long serialNumber;
	private Timestamp time;
	// digest
	// firma
	
	public Marca(String idUser, long serialNumber, Timestamp time) {
		this.idUser = idUser;
		this.serialNumber = serialNumber;
		this.time = time;
		
	}
	
	public String getIdUser() {
		return idUser;
	}
	public void setIdUser(String idUser) {
		this.idUser = idUser;
	}
	public long getSerialNumber() {
		return serialNumber;
	}
	public void setSerialNumber(long serialNumber) {
		this.serialNumber = serialNumber;
	}
	public Timestamp getTime() {
		return time;
	}
	public void setTime(Timestamp time) {
		this.time = time;
	}

}
