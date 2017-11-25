package progetto3;

import java.util.ArrayList;

public class Marca {
	private String idUser;
	private long serialNumber;
	private long timest;
	private byte[] digest;
	private byte[] sig;
	private ArrayList<LinkedInfoUnit> linkedInformation;
	
	public Marca(String idUser, long serialNumber, long timest, byte[] digest, byte[] sig, ArrayList<LinkedInfoUnit> linkedInformation) {
		this.idUser = idUser;
		this.serialNumber = serialNumber;
		this.timest = timest;
		this.digest = digest;
		this.sig = sig;
		this.linkedInformation = linkedInformation;	
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
	public ArrayList<LinkedInfoUnit> getLinkedInformation() {
		return linkedInformation;
	}
}
