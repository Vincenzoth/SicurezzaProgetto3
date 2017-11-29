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
	private String algorithmHashTree;
	private String algorithHashSuper;
	
	/**
	 * Costruttore della classe 
	 * @param idUser identificativo del mittente 
	 * @param serialNumber numero di serie della marca temporale
	 * @param timest data e ora un cui la marca è stata generata
	 * @param digest il digest calcolato dalla TSA partendo da quello fornito dal richiedente
	 * @param linkedInformation
	 * @param algorithmSignature tipo di algoritmo di firma della marca temporale 
	 * @param algorithmHashTree tipo di algoritmo della funzione hash per il Merkle tree
	 * @param algorithmHashSuper tipo di algoritmo della funzione hash per il Super Hash
	 */
	public Marca(String idUser, long serialNumber, long timest, byte[] digest, String rootHashValue, String SHV_pre, String SHV, ArrayList<LinkedInfoUnit> linkedInformation, String algorithmSignature, String algorithmHashTree, String algorithmHashSuper) {
		this.idUser = idUser;
		this.serialNumber = serialNumber;
		this.timest = timest;
		this.digest = digest;
		this.rootHashValue = rootHashValue;
		this.superHV_prev = SHV_pre;
		this.superHV = SHV;
		this.linkedInformation = linkedInformation;	
		this.algorithSignature = algorithmSignature;
		this.algorithmHashTree = algorithmHashTree;
		this.algorithHashSuper = algorithmHashSuper;
	}
	
	
	/**
	 * Metodo get che restituisce l'identificativo dell'utente
	 * @return identificativo dell'utente
	 */
	public String getIdUser() {
		return idUser;
	}
	
	/**
	 * Metdodo che setta l'identificativo dell'utente
	 * @param idUser identificativo dell'utente
	 */
	public void setIdUser(String idUser) {
		this.idUser = idUser;
	}
	/**
	 * Metodo di get che restituisce il numero seriale della marca
	 * @return numero seriale della marca
	 */
	public long getSerialNumber() {
		return serialNumber;
	}
	/**
	 * Metodo che setta il numero seriale dlela marca
	 * @param serialNumber numero seriale della marca
	 */
	public void setSerialNumber(long serialNumber) {
		this.serialNumber = serialNumber;
	}
	/**
	 * Metodo di get che restituisce il timestamp della marca
	 * @return time stamp
	 */
	public long getTime() {
		return timest;
	}
	/**
	 * Metodo che setta il time stamp 
	 * @param time time stamp
	 */
	public void setTime(long time) {
		this.timest = time;
	}
	
	/**
	 * Metodo che restituisce il digest 
	 * @return digest
	 */
	public byte[] getDigest() {
		return digest;
	}
	public ArrayList<LinkedInfoUnit> getLinkedInformation() {
		return linkedInformation;
	}
	/**
	 * Metodo che restituisce il tipo di algoritmo di firma della marca temporale 
	 * @return tipo di algorimo della firma
	 */
	public String getAlgorithSignature() {
		return algorithSignature;
	}
	
	/**
	 * Metodo che restituisce il root hash value
	 * @return root hash value
	 */
	public String getRootHashValue() {
		return rootHashValue;
	}
	/**
	 * Metodo che restituisce il super hash value  precedente 
	 * @return super hash value 
	 */
	public String getSuperHV_prev() {
		return superHV_prev;
	}
	/**
	 * Metodo che restituisce il super hash value corrente
	 * @return super hash value
	 */
	public String getSuperHV() {
		return superHV;
	}

	/**
	 * Il metodo restituisce l'algoritmo utilizzato per le funzioni hash del Merkle tree
	 * @return l'algoritmo utilizzato per le funzioni hash del Merkle tree
	 */
	public String getAlgorithmHashTree() {
		return algorithmHashTree;
	}

	/**
	 * Il metodo restituisce l'algoritmo utilizzato per calcolare il super Hash value
	 * @return l'algoritmo utilizzato per calcolare il super Hash value
	 */
	public String getAlgorithHashSuper() {
		return algorithHashSuper;
	}
	
	
	
}
