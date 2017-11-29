package progetto3;

import java.io.Serializable;


public class Request implements Serializable {
	private static final long serialVersionUID = 2L;
	private String idUser;
	private byte[] h; 
	
	/**
	 * Costruttore della classe 
	 * @param idUser Identificativo del mittente 
	 * @param h contenuto della richiesta in array di byte
	 */
	public Request(String idUser, byte[] h) {
		this.idUser = idUser;
		this.h = h;
	}
	
	/**
	 * Metodo che restituisce l'identificativo dell'utente 
	 * @return
	 */
	public String getIdUser() {
		return idUser;
	}

	/**
	 * Metodo che restituisce l'hash value 
	 * @return hash value
	 */
	public byte[] getH() {
		return h;
	}
}
