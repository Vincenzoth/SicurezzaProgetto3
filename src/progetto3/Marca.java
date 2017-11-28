package progetto3;

import java.util.ArrayList;

public class Marca {
	private String idUser;
	private long serialNumber;
	private long timest;
	private byte[] digest;
	private String rootHashValue;
	private String superHV_prev;
	private String superHV;
	private ArrayList<LinkedInfoUnit> linkedInformation;
	private String algorithSignature;
	
	/**
	 * Costruttore della classe 
	 * @param idUser identificativo del mittente 
	 * @param serialNumber numero di serie della marca temporale
	 * @param timest data e ora un cui la marca è stata generata
	 * @param digest il digest calcolato dalla TSA partendo da quello fornito dal richiedente
	 * @param linkedInformation
	 * @param algorithmSignature tipo di algoritmo di firma della marca temporale 
	 */
	public Marca(String idUser, long serialNumber, long timest, byte[] digest, String rootHashValue, String SHV_pre, String SHV, ArrayList<LinkedInfoUnit> linkedInformation, String algorithmSignature) {
		this.idUser = idUser;
		this.serialNumber = serialNumber;
		this.timest = timest;
		this.digest = digest;
		this.rootHashValue = rootHashValue;
		this.superHV_prev = SHV_pre;
		this.superHV = SHV;
		this.linkedInformation = linkedInformation;	
		this.algorithSignature = algorithmSignature;
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
	public ArrayList<LinkedInfoUnit> getLinkedInformation() {
		return linkedInformation;
	}
	public String getAlgorithSignature() {
		return algorithSignature;
	}
	public String getRootHashValue() {
		return rootHashValue;
	}
	public String getSuperHV_prev() {
		return superHV_prev;
	}
	public String getSuperHV() {
		return superHV;
	}
	
	
	
}
