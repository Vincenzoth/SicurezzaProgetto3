package keyRing;

import java.io.Serializable;

import javax.crypto.SealedObject;

public class User implements Serializable {

	private static final long serialVersionUID = 1L;

	private String ID;
	private byte[] salt;
	private SealedObject info;


	public User(String ID, byte[] salt, SealedObject info) {
		this.ID = ID;
		this.salt = salt;	
		this.info = info;
	}

	public String getID() {
		return ID;
	}
	public void setID(String id) {
		ID = id;
	}
	public byte[] getSalt() {
		return salt;
	}
	public void setSalt(byte[] salt) {
		this.salt = salt;
	}
	public SealedObject getInfo() {
		return info;
	}
	public void setInfo(SealedObject info) {
		this.info = info;
	}	

}
