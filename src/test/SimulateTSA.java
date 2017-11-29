package test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

import progetto3.Request;

import progetto3.TSA;

public class SimulateTSA {
	final static int NUM_REQUESTS = 100;
	
	final static String DUMMY_HASH_ALG = "SHA-1";
	final static String DOC_HASH_ALG = "SHA-256";
	final static String CIPHER_ALG = "RSA";
	final static String SIGNATURE_ALG = "DSA";
	final static int KEY_LEN_COD = 2048;
	final static int KEY_LEN_SIG = 2048;

	final static String BASE_PATH = Paths.get(System.getProperty("user.dir")).toString();
	final static String KEYS_PATH = BASE_PATH + "/data/keys/";
	final static String FILE_PR_KEY_COD = KEYS_PATH + "private/prCod.key";
	final static String FILE_PUB_KEY_COD = KEYS_PATH + "public/pubCod.key";
	final static String FILE_PR_KEY_SIG = KEYS_PATH + "private/prSig.key";
	final static String FILE_PUB_KEY_SIG = KEYS_PATH + "public/pubSig.key";
	
	final static String CIPHER_MODE = "RSA/ECB/PKCS1Padding"; 
	final static String SIGNATURE_MODE = "SHA256WithDSA"; 

	public static void main(String[] args) {
		System.out.println("Inizio simulazione TSA -------------");
		TSA myTSA = null;

		try {
			myTSA = initTSA();
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | IOException | NoSuchPaddingException e) {
			System.err.println("Errore nell'inizializzare la TSA!");
		}

		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(CIPHER_MODE);
			byte[] keyPublicCodByte  = Files.readAllBytes(Paths.get(FILE_PUB_KEY_COD));
			KeyFactory factoryRsa  =  KeyFactory.getInstance(CIPHER_ALG);
			PublicKey keyPublicCod = factoryRsa.generatePublic(new X509EncodedKeySpec(keyPublicCodByte));
			cipher.init(Cipher.ENCRYPT_MODE, keyPublicCod);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | InvalidKeySpecException | InvalidKeyException e2) {
			System.err.println("Errore nell'inizializzare del cifrario per cifrare le richieste!");
		}


		ArrayList<SealedObject> requests = new ArrayList<SealedObject>();
		// costruisci l'rray di richieste
		
		Request r = null;

		MessageDigest md;
		try {
			md = MessageDigest.getInstance(DOC_HASH_ALG);
			byte[] testDoc = Files.readAllBytes(Paths.get(ValidateTimeStamp.DOC_TO_TEST));
			md.update(testDoc);
			byte[] hashTest = md.digest();
			r = new Request("UserTest", hashTest);

			requests.add(new SealedObject(r,cipher));
		} catch (NoSuchAlgorithmException | IOException | IllegalBlockSizeException e) {
			e.printStackTrace();;
			System.err.println("Errore nel generare prima richiesta!");
		}	

		try {
			for (int i = 1; i<NUM_REQUESTS; i++) {
				byte[] hash = generateHash();
				r = new Request("user"+i, hash);
				requests.add(new SealedObject(r,cipher));
			}
		} catch (NoSuchAlgorithmException | IllegalBlockSizeException | IOException e) {
			System.err.println("Errore nell'inizializzare il vettore di richieste!");
		}


		try {
			myTSA.generateMarche(requests);

		} catch (NoSuchAlgorithmException | SignatureException | IOException | ClassNotFoundException | IllegalBlockSizeException | BadPaddingException e) {
			System.err.println("Errore nelgenerare le marche!");
		}


		System.out.println("Fine simulazione TSA  -------------");

	}
	
	
	
	public static TSA initTSA() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException {
		File f = new File(FILE_PR_KEY_SIG);
		PrivateKey privKeyVer;
		PrivateKey privKeyCod;

		if(f.exists() && !f.isDirectory()) { 
			// leggiamo la chiave di firma 
			byte[] keyBytes = Files.readAllBytes(Paths.get(FILE_PR_KEY_SIG));
			KeyFactory kf = KeyFactory.getInstance(SIGNATURE_ALG);
			privKeyVer = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
			//leggiamo la chiave di cifratura
			byte[] keyBytesCod = Files.readAllBytes(Paths.get(FILE_PR_KEY_COD));
			kf = KeyFactory.getInstance(CIPHER_ALG);
			privKeyCod = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytesCod));
		}else {
			// Genera chiavi cifrario TSA
			KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance(CIPHER_ALG);
			keyGenRSA.initialize(KEY_LEN_COD, new SecureRandom());
			KeyPair pairRSA = keyGenRSA.generateKeyPair();
			// Genera chiavi firma TSA
			KeyPairGenerator keyGenSig = KeyPairGenerator.getInstance(SIGNATURE_ALG);
			keyGenSig.initialize(KEY_LEN_SIG, new SecureRandom());
			KeyPair pairDSA = keyGenSig.generateKeyPair();

			// scrivi i file della chiave
			FileOutputStream fos;
			File keysPath = new File(KEYS_PATH+"/private/");
			if(!keysPath.exists()) { 			 
				keysPath.mkdirs();
				keysPath = new File(KEYS_PATH+"/public/");
				keysPath.mkdirs();
			}
			fos = new FileOutputStream(new File(FILE_PR_KEY_COD));
			fos.write(pairRSA.getPrivate().getEncoded());
			fos.flush();
			fos = new FileOutputStream(new File(FILE_PUB_KEY_COD));
			fos.write(pairRSA.getPublic().getEncoded());
			fos.flush();
			fos = new FileOutputStream(new File(FILE_PR_KEY_SIG));
			fos.write(pairDSA.getPrivate().getEncoded());
			fos.flush();
			fos = new FileOutputStream(new File(FILE_PUB_KEY_SIG));
			fos.write(pairDSA.getPublic().getEncoded());
			fos.flush();
			fos.close();

			privKeyVer = pairDSA.getPrivate();
			privKeyCod = pairRSA.getPrivate();
		}

		return new TSA(privKeyVer, SIGNATURE_MODE,privKeyCod,CIPHER_MODE );
	}
	
	public static byte[] generateHash() throws NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		byte inputBytes[] = new byte[1024];
		random.nextBytes(inputBytes);

		MessageDigest digest = MessageDigest.getInstance(DUMMY_HASH_ALG);

		return digest.digest(inputBytes);
	}

}
