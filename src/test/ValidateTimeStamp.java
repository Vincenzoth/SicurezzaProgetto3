package test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.json.simple.parser.ParseException;

import progetto3.*;

public class ValidateTimeStamp {
	final static String BASE_PATH = Paths.get(System.getProperty("user.dir")).toString();
	final static String KEYS_PATH = BASE_PATH + "/data/keys/";
	final static String FILE_PR_KEY_COD = KEYS_PATH + "private/prCod.key";
	final static String FILE_PUB_KEY_COD = KEYS_PATH + "public/pubCod.key";
	final static String FILE_PR_KEY_SIG = KEYS_PATH + "private/prSig.key";
	final static String FILE_PUB_KEY_SIG = KEYS_PATH + "public/pubSig.key";
	
	final static String DOC_TO_TEST = BASE_PATH + "/data/documento.pdf";
	final static String FILE_TS_TO_TEST = BASE_PATH + "/data/marche/0_UserTest_29-11-2017_19-29-15-816.tms";
	
	public static void main(String[] args) {
		System.out.println("---- VERIFICA UNA MARCA --------");
		System.out.println();
		System.out.println("marca: " + FILE_TS_TO_TEST);
		System.out.println();

		MessageDigest md;
		byte[] hashTest = null;
		try {
			md = MessageDigest.getInstance(SimulateTSA.DOC_HASH_ALG);
			byte[] testDoc = Files.readAllBytes(Paths.get(DOC_TO_TEST));
			md.update(testDoc);
			hashTest = md.digest();
		} catch (NoSuchAlgorithmException | IOException e1) {
			System.err.println("Errore nel generare hash del documento!");
		}

		try {
			//Leggiamo chiave
			byte[] keyBytes = Files.readAllBytes(Paths.get(FILE_PUB_KEY_SIG));
			KeyFactory kf = KeyFactory.getInstance("DSA");
			PublicKey sigKey = kf.generatePublic(new X509EncodedKeySpec(keyBytes));

			Validator val = new Validator(sigKey);

			try {
				if(val.checkRootHash(FILE_TS_TO_TEST, hashTest))
					System.out.println("Il root Hash Value è valido");
				else
					System.out.println("Il root hash value non è valido");
			}catch(MyException  e) {
				System.err.println(e.getMessage());
			}

			try {
				if(val.checkSuperHash(FILE_TS_TO_TEST))
					System.out.println("Il Super Hash Value è valido");
				else
					System.out.println("Il Super hash value non è valido");
			} catch (MyException  e) {
				System.err.println(e.getMessage());
			}

			try {
				val.checkSuperHashList( FILE_TS_TO_TEST,
										BASE_PATH+"/data/rootHashValues", 
										BASE_PATH+"/data/superHashValues");
				System.out.println("La catena dei Super Hash Value è valida!");
			} catch (MyException | IOException | ParseException e) {
				System.err.println(e.getMessage());
			}

		} catch (InvalidKeyException | SignatureException | ParseException | NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			System.err.println("Errore generico nella validazione!");
		} 

	}

}
