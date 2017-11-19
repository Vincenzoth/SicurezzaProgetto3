package keyRing;

import java.io.Serializable;
import java.security.PrivateKey;
import java.util.HashMap;

import javax.crypto.SecretKey;

public class PersonalInfo implements Serializable{
	private static final long serialVersionUID = 2L;

	private PrivateKey privKeyCod;
	private PrivateKey privKeyVer;
	private HashMap<String, String> sitesPasswords;
	private HashMap<String, SecretKey> simmetricKeys;

	
	public PersonalInfo() {
		this.sitesPasswords = new HashMap<String,String>();
		this.simmetricKeys = new HashMap<String, SecretKey>();
	}
	
	
	public PrivateKey getPrivKeyCod() {
		return privKeyCod;
	}
	public void setPrivKeyCod(PrivateKey privKeyCod) {
		this.privKeyCod = privKeyCod;
	}
	public PrivateKey getPrivKeyVer() {
		return privKeyVer;
	}
	public void setPrivKeyVer(PrivateKey privKeyVer) {
		this.privKeyVer = privKeyVer;
	}
	
	public HashMap<String, String> getSitesPasswords() {
		return this.sitesPasswords;
	}
	public HashMap<String, SecretKey> getSimmetricKeys() {
		return simmetricKeys;
	}

}
