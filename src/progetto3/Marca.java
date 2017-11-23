package progetto3;

import java.sql.Timestamp;

public class Marca {
	private String idUser;
	private long serialNumber;
	private Long timest;
	private byte[] digest;
	private byte[] sig;
	// digest
	// firma
	
	public Marca(String idUser, long serialNumber, long timest, byte[] digest, byte[] sig) {
		this.idUser = idUser;
		this.serialNumber = serialNumber;
		this.timest = timest;
		this.digest = digest;
		this.sig = sig;
		
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
	public long getTime() {
		return timest;
	}
	public void setTime(long time) {
		this.timest = time;
	}
	public byte[] getDigest() {
		return digest;
	}
	public byte[] getSig() {
		return sig;
	}
	

}
