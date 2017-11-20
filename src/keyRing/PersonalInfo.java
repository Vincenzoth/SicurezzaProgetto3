package keyRing;

import java.io.Serializable;
import java.security.PrivateKey;
import java.util.HashMap;

import javax.crypto.SecretKey;

public class PersonalInfo implements Serializable{
	private static final long serialVersionUID = 2L;

	private HashMap<String, PrivateKey> privKeyCod;
	private HashMap<String, PrivateKey> privKeyVer;
	private HashMap<String, String> sitesPasswords;
	private HashMap<String, SecretKey> simmetricKeys;

	
	public PersonalInfo() {
		this.privKeyCod = new HashMap<String,PrivateKey>();
		this.privKeyVer = new HashMap<String,PrivateKey>();
		this.sitesPasswords = new HashMap<String,String>();
		this.simmetricKeys = new HashMap<String, SecretKey>();
	}
	
	public HashMap<String,PrivateKey> getPrivKeyCod() {
		return privKeyCod;
	}
	
	public HashMap<String,PrivateKey> getPrivKeyVer() {
		return privKeyVer;
	}
	public HashMap<String, String> getSitesPasswords() {
		return this.sitesPasswords;
	}
	public HashMap<String, SecretKey> getSimmetricKeys() {
		return simmetricKeys;
	}

}
