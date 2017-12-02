package test;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import keyRing.*;

public class TestKeyRing {

	public static void main(String[] args) {
		try {
			// gestiamo gli utenti
			KeyRing kr = new KeyRing();

			//aggiungi utenti
			if(kr.newUser("qwerty", "giu"))
				System.out.println("utente giu aggiunto");
			else
				System.out.println("giu Non aggiunto, già presente uno utente con lo stesso ID");

			if( kr.newUser("asdf", "mic"))
				System.out.println("utente mic aggiunto");
			else
				System.out.println("mic Non aggiunto, gia presente un utente con lo stesso ID");

			if( kr.newUser("passe", "vin"))
				System.out.println("utente vin aggiunto");
			else
				System.out.println("vin Non aggiunto, gia presente un utente con lo stesso ID");

			// rimozione utenti
			if(kr.removeUser("vin"))
				System.out.println("utente vin rimosso correttamente");
			else
				System.out.println("Errore nella rimozione dell'utente vin");


			// test accesso informazioni
			try {
				System.out.println("\n -------------- Utente 'vin'");
				KeyRing kr_vin = new KeyRing("vin", "ass");
			}catch(KeyRingException e) {
				System.err.println(e.getMessage());
			}

			System.out.println("\n -------------- Utente 'giu'");
			KeyRing kr_giu = new KeyRing("giu", "qwerty");

			// -------PASSWORD
			kr_giu.addSitePasword("facebook", "fb_passw0rd");
			System.out.println("Password per facebook: " + kr_giu.getSitePassword("facebook"));

			// -------SIMMETRIK KEY
			KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
			SecretKey desKey = keygenerator.generateKey();

			kr_giu.addSimmetricKey("DesKey1", desKey);

			System.out.println("Chiave simmetrica giu DesKey1: " + kr_giu.getSimmetricKey("DesKey1"));


			// ------- ASIMMETRIK KEY
			KeyPairGenerator keygeneratorRSA = KeyPairGenerator.getInstance("RSA");
			keygeneratorRSA.initialize(2048, new SecureRandom());
			KeyPair pair = keygeneratorRSA.generateKeyPair();

			kr_giu.addPublicKey("giu", "RSA1",pair.getPublic());

			System.out.println("Chiave pubblica giu RSA1: " + kr_giu.getPublicKey("giu", "RSA1"));


			System.out.println("\n -------------- Utente 'mic'");
			KeyRing kr_mic = new KeyRing("mic", "asdf");

			kr_mic.addSitePasword("facebook", "MichEl3");
			//kr_mic.updateSitePasword("facebook", "asdA");
			System.out.println("Password per facebook: " + kr_mic.getSitePassword("facebook"));

			// ------- ASIMMETRIK KEY
			keygeneratorRSA.initialize(1024, new SecureRandom());
			KeyPair pair2 = keygeneratorRSA.generateKeyPair();

			kr_mic.addPublicKey("giu", "RSA1",pair.getPublic());
			kr_mic.addPublicKey("mic", "RSA2",pair2.getPublic());

			System.out.println("Chiave pubblica giu RSA1: " + kr_mic.getPublicKey("giu", "RSA1"));
			System.out.println("Chiave pubblica mic RSA2: " + kr_mic.getPublicKey("mic", "RSA2"));



		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | IOException | ClassNotFoundException | BadPaddingException | KeyRingException e) {
			e.printStackTrace();
			System.err.println("errore: "+e.getMessage());
		}





	}

}
