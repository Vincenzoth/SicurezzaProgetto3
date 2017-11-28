package progetto3;

import java.io.File;
import java.io.FileNotFoundException;
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

import org.json.simple.parser.ParseException;

public class Simula {
	final static boolean simulaTSA = true;
	final static boolean valutaMarca = true;


	final static String PATH = Paths.get(System.getProperty("user.dir")).toString();

	final static String DUMMY_HASH_ALG = "SHA-1";
	final static String CIPHER_ALG = "RSA";
	final static String SIGNATURE_ALG = "DSA";
	final static int KEY_LEN_COD = 1024;
	final static int KEY_LEN_SIG = 1024;

	final static String BASE_PATH = Paths.get(System.getProperty("user.dir")).toString();
	final static String KEYS_PATH = BASE_PATH + "/data/keys/";
	final static String FILE_PR_KEY_COD = KEYS_PATH + "private/prCod.key";
	final static String FILE_PUB_KEY_COD = KEYS_PATH + "public/pubCod.key";
	final static String FILE_PR_KEY_SIG = KEYS_PATH + "private/prSig.key";
	final static String FILE_PUB_KEY_SIG = KEYS_PATH + "public/pubSig.key";



	public static void main(String[] args) {
		if(simulaTSA) {
			TSA myTSA = null;

			try {
				myTSA = initTSA();


			} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
				e.printStackTrace();
				System.err.println("Errore nell'inizializzare la TSA!");
			}


			ArrayList<Richiesta> requests = new ArrayList<Richiesta>();
			// costruisci l'rray di richieste
			int numRequest = 10;
			String testDoc = "Questa stringa vuole essere un documento del quale si richede una marca temporale!";
			MessageDigest md;
			try {
				md = MessageDigest.getInstance(DUMMY_HASH_ALG);
				byte[] hashTest = md.digest(testDoc.getBytes());
				requests.add(new Richiesta("UserTest", hashTest));
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
				System.err.println("Errore nel generare prima richiesta!");
			}		

			try {
				for (int i = 1; i<numRequest; i++) {
					//trova i h random
					byte[] hash = generateHash();
					requests.add(new Richiesta("user"+i, hash));
				}
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				System.err.println("Errore nell'inizializzare il vettore di richieste!");
			}


			try {
				myTSA.generateMarche(requests);

			} catch (NoSuchAlgorithmException | SignatureException | IOException e) {
				e.printStackTrace();
				System.err.println("Errore nelgenerare le marche!");
			}
			

			System.out.println("Fine simulazione TSA");
		}


		// verifica
		if(valutaMarca) {
			System.out.println("---- VERIFICA UNA MARCA --------");

			String testDoc = "Questa stringa vuole essere un documento del quale si richede una marca temporale!";
			MessageDigest md;
			byte[] hashTest = null;
			try {
				md = MessageDigest.getInstance(DUMMY_HASH_ALG);
				hashTest = md.digest(testDoc.getBytes());
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
				System.err.println("Errore nel generare hash del documento!");
			}
			
			try {
				//Leggiamo chiave
				byte[] keyBytes = Files.readAllBytes(Paths.get(FILE_PUB_KEY_SIG));
				KeyFactory kf = KeyFactory.getInstance("DSA");
				PublicKey sigKey = kf.generatePublic(new X509EncodedKeySpec(keyBytes));
						
				Validator val = new Validator("SHA-256", sigKey);

				String rootHashValue = "c8090cb33bb5507c2dd3424f20920d60255de6b0ef78c3fc07b4a52b4e148286";

				if(val.check(PATH+"/data/marche/0_UserTest_27-11-2017_22-24-30-292.txt", hashTest, rootHashValue))
					System.out.println("Il root Hash Value è valido");
				else
					System.out.println("Il root hash value non è valido");

			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (ParseException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			} catch (MyException e) {
				e.printStackTrace();
				System.err.println(e.getMessage());
				
			}
		}

	}

	public static TSA initTSA() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException {
		File f = new File(FILE_PR_KEY_SIG);
		PrivateKey privKey;

		if(f.exists() && !f.isDirectory()) { 
			// leggiamo la chiave
			byte[] keyBytes = Files.readAllBytes(Paths.get(FILE_PR_KEY_SIG));
			KeyFactory kf = KeyFactory.getInstance("DSA");
			privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
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

			privKey = pairDSA.getPrivate();
		}

		return new TSA(privKey);
	}

	public static byte[] generateHash() throws NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		byte inputBytes[] = new byte[1024];
		random.nextBytes(inputBytes);

		MessageDigest digest = MessageDigest.getInstance(DUMMY_HASH_ALG);

		return digest.digest(inputBytes);
	}

	public static void verfy(Marca m, byte[] hash, byte[] rootHash)	{
		// ricalcola il rootHash con hash che calcoli tu
		// e controlla che questo sia uguale a rootHash pubblicato
	}
}
