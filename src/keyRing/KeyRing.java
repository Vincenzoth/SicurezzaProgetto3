package keyRing;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * La classe rappresenta un key ring. Permette di aggiungere o rimuovere utenti al sistema,
 * e permette di ottenere le informazioni private di uno specifico utente. 
 *
 */
public class KeyRing {
	final static String PATH = Paths.get(System.getProperty("user.dir")).toString();
	final static String FILE_NAME = PATH + "/data/keyRing.kr";
	final static String CIPHER = "DESede/ECB/PKCS5Padding";

	private Cipher cipher;
	private PersonalInfo pi = null;
	private String ID;
	private SecretKey key;
	private HashMap<String,User> keys;


	/**
	 * Costruttore senza parametri.
	 * Costruisce un oggetto capace di gestire tutti gli utenti ma non ha accesso alle informazioni private di un singolo utente.
	 * @param password (permette di generare la chiave utilizzata nel cifrario)
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * @throws FileNotFoundException 
	 * @throws InvalidKeyException 
	 */
	public KeyRing() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, FileNotFoundException, ClassNotFoundException, IOException {
		this.cipher = Cipher.getInstance(CIPHER);

		// inizializza mappa
		keys = new HashMap<String,User>();

		//popola la mappa
		loadMap();
	}

	/**
	 * Costruisce un oggetto capace di gestire avere accesso accesso alle informazioni private di un singolo utente.
	 * @param ID (Identificativo dell 'user di cui si vuole costruire il key ring)
	 * @param password (password per generare la chiave di decodifica delle informazioni private)
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * @throws FileNotFoundException 
	 * @throws InvalidKeyException 
	 * @throws KeyRingException 
	 */
	public KeyRing (String ID, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, FileNotFoundException, IOException, ClassNotFoundException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, KeyRingException {
		this.cipher = Cipher.getInstance(CIPHER);
		this.ID = ID;

		// inizializza mappa
		keys = new HashMap<String,User>();

		//popola la mappa
		loadMap();

		// ottieni informazioni utente
		User us = keys.get(ID);

		// genera la chiave
		try {
			this.key = loadKey(password.toCharArray(), us.getSalt());
		}catch(NullPointerException e) {
			throw new KeyRingException("Utente "+ID+" non presente nel sistema");
		}
		// inizializza cifrario
		this.cipher.init(Cipher.DECRYPT_MODE, this.key);

		try {
			pi = (PersonalInfo) us.getInfo().getObject(this.cipher);}
		catch(Exception e) {
			throw new KeyRingException("Impossibile decifrare le informazioni!");
		}

	}

	/**
	 * Genera la chiave per decifrare le informazioni private di un utente a partire dalla password e salt passati come parametri
	 * @return secretKey
	 * @param password (array di char della password per generare la chiave di cifratura)
	 * @param salt (array di byte da utilizzare come salt per generare la chiave di cifratura)
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	private SecretKey loadKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException{		
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

		// Specifica della chiave
		KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 192);

		// Genera una chiave generica
		SecretKey tmp = factory.generateSecret(keySpec);

		// Genera una chiave DESede
		SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), "DESede");

		return secretKey;
	}

	/**
	 * Se il file delle chiavi � presente, legge le informazioni e le utilizza
	 * per popolare la mappa degli utenti
	 */
	@SuppressWarnings("unchecked")
	private void loadMap() throws InvalidKeyException, FileNotFoundException, IOException, ClassNotFoundException {
		File f = new File(FILE_NAME);
		if(f.exists() && !f.isDirectory()) { 
			// il file delle chiavi esiste

			ObjectInputStream ois;
			ois = new ObjectInputStream( new FileInputStream(FILE_NAME) );
			keys = (HashMap<String,User>) ois.readObject();
			ois.close();
		}
	}

	/**
	 * Inserisce un nuovo utente all�interno della mappa degli utenti e all�interno del file delle chiavi
	 * @param password (password che verr� utilizzata per generare la chiave dell'utente con cui cifrare le informazioni private)
	 * @param newID (ID nuovo utente)
	 * @return true se l'inserimento va a buon fine, false se ID gi� presente 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 */
	public boolean newUser(String password, String newID) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException {
		// Genera un salt
		SecureRandom r = new SecureRandom();
		byte[] salt = new byte[16];
		r.nextBytes(salt);

		//genera chiave e inizializza il cifrario
		SecretKey k = loadKey(password.toCharArray(), salt);
		this.cipher.init(Cipher.ENCRYPT_MODE, k);

		// genera blocco informazioni cifrate
		PersonalInfo info = new PersonalInfo();
		SealedObject infoEncr = new SealedObject(info, this.cipher);


		// aggiungi alla mappa
		User retValue = keys.put(newID, new User(newID, salt, infoEncr));

		if( retValue == null) {
			// aggiungi al file	
			writeFile();
		}

		return retValue != null ? false : true;
	}

	/**
	 * Rimuove l'utente identificato dall'id userID dalla mappa e dal file delle chiavi.
	 * @param userID (ID dell'utente da rimuovere)
	 * @return true se la rimozione va a buon fine altrimenti false
	 */
	public boolean removeUser(String userID) throws InvalidKeyException, FileNotFoundException, IOException {

		User retValue = keys.remove(userID);

		if( retValue != null) {
			// aggiungi al file	
			writeFile();
		}

		return retValue == null ? false : true;

	}



	/**
	 * Restituisce un array contente tutti gli ID degli utenti presenti nella mappa
	 * @return Stringa di array contente gli ID degli utenti
	 */
	public String[] getAllUsers(){
		ArrayList<String> usersID = new ArrayList<String>(); 
		for (User user: keys.values()){			
			usersID.add(user.getID());			
		}

		return usersID.toArray(new String[usersID.size()]);
	}

	/**
	 * Il metodo scrive le informazioni della mappa degli utenti sul file.
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private void writeFile() throws FileNotFoundException, IOException {
		File keysFile = new File(FILE_NAME);
		if(!keysFile.exists()) 			 
			keysFile.getParentFile().mkdirs();

		ObjectOutputStream oss;
		oss = new ObjectOutputStream(new FileOutputStream(keysFile));
		oss.writeObject(keys);
		oss.flush();
		oss.close();
	}

	/**
	 * Il metodo aggiorna il file su disco
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	private void updateFile() throws InvalidKeyException, IllegalBlockSizeException, IOException {
		this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
		SealedObject infoEncr = new SealedObject(pi, this.cipher);

		// aggiorna mappa
		keys.get(this.ID).setInfo(infoEncr);

		// riscrivi file
		writeFile();
	}



	/**
	 * Il metodo aggiunge una password alle informazioni private dell'utente
	 * 
	 * @param idSite
	 * @param password
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public String addSitePasword(String idSite, String password) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		String returnValue = pi.getSitesPasswords().put(idSite, password);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo aggiorna la password dell'utente.
	 * 
	 * @param idSite
	 * @param password
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public String updateSitePasword(String idSite, String password) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		String returnValue = pi.getSitesPasswords().replace(idSite, password);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo recupera la password identificata dal parametro idSite dalle informazioni private dell'utente.
	 * 
	 * @param idSite
	 * @return
	 */
	public String getSitePassword(String idSite) {
		return this.pi.getSitesPasswords().get(idSite);
	}

	/**
	 * Il metodo rimuove la password identificata dal parametro idSite dalle informazioni private dell'utente.
	 * 
	 * @param idSite
	 * @return
	 */
	public String removeSite(String idSite) {
		return this.pi.getSitesPasswords().remove(idSite);
	}

	/**
	 * Il metodo aggiunge la chiave simmetrica passata come parametro key e identificata dal parametro IdKey alle informazioni private dell'utente.
	 * 
	 * @param IdKey
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public SecretKey addSimmetricKey(String IdKey, SecretKey key) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		SecretKey returnValue = pi.getSimmetricKeys().put(IdKey, key);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo aggiorna la chiave simmetricaidentificata dal parametro IdKey con la nuova chiave passata come parametro newKey.
	 * 
	 * @param IdKey
	 * @param newKey
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public SecretKey updateSimmetricKey(String IdKey, SecretKey newKey) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		SecretKey returnValue = pi.getSimmetricKeys().replace(IdKey, newKey);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo restituisce la chiave simmetrica identificata dal parametro IdKey
	 * 
	 * @param IdKey
	 * @return
	 */
	public SecretKey getSimmetricKey(String IdKey) {
		return pi.getSimmetricKeys().get(IdKey);
	}

	/**
	 * Il metodo rimuove la chiave simmetrica identificata dal parametro IdKey
	 * 
	 * @param IdKey
	 * @return
	 */
	public SecretKey removeSimmetricKey(String IdKey) {
		return pi.getSimmetricKeys().remove(IdKey);
	}

	/**
	 * Il metodo aggiunge la chiave privata di codifica passata come parametro key e identificata dal parametro IdKey alle informazioni private dell'utente.
	 * 
	 * @param IdKey
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public PrivateKey addPrivateKeyCod(String IdKey, PrivateKey key) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		PrivateKey returnValue = pi.getPrivKeyCod().put(IdKey, key);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo aggiorna la chiave privata di codifica identificata dal parametro IdKey con la nuova chiave passata come parametro newKey.
	 * 
	 * @param IdKey
	 * @param newKey
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public PrivateKey updatePrivateKeyCod(String IdKey, PrivateKey newKey) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		PrivateKey returnValue = pi.getPrivKeyCod().replace(IdKey, newKey);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo restituisce la chiave privata di codifica identificata dal parametro IdKey.
	 * 
	 * @param IdKey
	 * @return
	 */
	public PrivateKey getPrivateKeyCod(String IdKey) {
		return pi.getPrivKeyCod().get(IdKey);
	}

	/**
	 * Il metodo rimuove la chiave privata di codifica identificata dal parametro IdKey.
	 * 
	 * @param IdKey
	 * @return
	 */
	public PrivateKey removePrivateKeyCod(String IdKey) {
		return pi.getPrivKeyCod().remove(IdKey);
	}

	/**
	 * Il metodo aggiunge la chiave privata di verifica passata come parametro key e identificata dal parametro IdKey alle informazioni private dell'utente.
	 * 
	 * @param IdKey
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public PrivateKey addPrivateKeyVer(String IdKey, PrivateKey key) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		PrivateKey returnValue = pi.getPrivKeyVer().put(IdKey, key);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo aggiorna la chiave privata di verifica identificata dal parametro IdKey con la nuova chiave passata come parametro newKey.
	 * 
	 * @param IdKey
	 * @param newKey
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public PrivateKey updatePrivateKeyVer(String IdKey, PrivateKey newKey) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		PrivateKey returnValue = pi.getPrivKeyVer().replace(IdKey, newKey);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo restituisce la chiave privata di verifica identificata dal parametro IdKey.
	 * 
	 * @param IdKey
	 * @return
	 */
	public PrivateKey getPrivateKeyVer(String IdKey) {
		return pi.getPrivKeyVer().get(IdKey);
	}

	/**
	 * Il metodo rimuove la chiave privata di verifica identificata dal parametro IdKey.
	 * 
	 * @param IdKey
	 * @return
	 */
	public PrivateKey removePrivateKeyVer(String IdKey) {
		return pi.getPrivKeyVer().remove(IdKey);
	}

	/**
	 * Il metodo aggiunge la chiave pubblica passata come parametro key e identificata dal parametro IdKey 
	 * appartenente all'utente identificato dal parametro IDuser alle informazioni private dell'utente.
	 * 
	 * @param IDuser
	 * @param IdKey
	 * @param key
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public PublicKey addPublicKey(String IDuser, String IdKey, PublicKey key) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		PublicKey returnValue = pi.getpublicKeys().put(IDuser, IdKey, key);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo aggiorna la chiave pubblica identificata dal parametro IdKey appartenente all'utente 
	 * identificato dal parametro IDuser con la chiave passato come parametro newKey
	 * 
	 * @param IDUser
	 * @param IdKey
	 * @param newKey
	 * @return
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public PublicKey updatePublicKey(String IDuser, String IdKey, PublicKey newKey) throws InvalidKeyException, IllegalBlockSizeException, IOException {
		PublicKey returnValue = pi.getpublicKeys().replace(IDuser, IdKey, newKey);

		updateFile();

		return returnValue;
	}

	/**
	 * Il metodo restituisce la chiave pubblica identificata dal parametro IdKey appartenente all'utente 
	 * identificato dal parametro IDuser.
	 * 
	 * @param IDUser
	 * @param IdKey
	 * @return
	 */
	public PublicKey getPublicKey(String IDuser, String IdKey) {
		return pi.getpublicKeys().get(IDuser, IdKey);
	}

	/**
	 * Il metodo rimuove la chiave pubblica identificata dal parametro IdKey appartenente all'utente 
	 * identificato dal parametro IDuser.
	 * 
	 * @param IDuser
	 * @param IdKey
	 * @return
	 */
	public PublicKey removePublicKey(String IDuser, String IdKey) {
		return pi.getpublicKeys().remove(IDuser, IdKey);
	}
}
