package progetto3;

import java.io.Serializable;

public class Richiesta implements Serializable {
	private String idUser;
	private byte[] h; //cif(h)
	
	public Richiesta(String idUser, byte[] h) {
		this.idUser = idUser;
		this.h = h;
	}

	public String getIdUser() {
		return idUser;
	}

	public byte[] getH() {
		return h;
	}
}
