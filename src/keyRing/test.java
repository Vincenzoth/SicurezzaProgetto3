package keyRing;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class test {

	public static void main(String[] args) {
		try {
			// gestiamo gli utenti
			KeyRing kr = new KeyRing();
			
			//aggiungi utenti
			boolean v = kr.newUser("qwerty", "giu");
			if(v)
				System.out.println("utente giu aggiunto");
			else
				System.out.println("giu Non aggiunto");
			
			
			v = kr.newUser("asdf", "mic");
			if(v)
				System.out.println("utente mic aggiunto");
			else
				System.out.println("mic Non aggiunto");
			
			
			
			System.out.println("\n ---- recupero giu");
			KeyRing kr_giu = new KeyRing("giu", "qwerty");
			// -------PASSWORD
			//kr_giu.addSitePasword("facebook", "bello_bello");
			//kr_giu.updateSitePasword("facebook", "BellA_BellA");
			System.out.println("Password per facebook: " + kr_giu.getSitePassword("facebook"));
			
			//System.out.println("le info sono essuno: " + kr.getSitePassword("facebook"));
			
			// -------SIMMETRIK KEY
			KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
			SecretKey desKey = keygenerator.generateKey();
			
			//kr_giu.addSimmetricKey("DesKey1", desKey);
			
			System.out.println("Chiave giu DesKey1: " + kr_giu.getSimmetricKey("DesKey1"));
			
			
			System.out.println("\n ---- recupero mic");
			KeyRing kr_mic = new KeyRing("mic", "asdf");
			
			kr_mic.addSitePasword("facebook", "MichEl");
			//kr_mic.updateSitePasword("facebook", "asdA");
			System.out.println("Password per facebook: " + kr_mic.getSitePassword("facebook"));
			
			//System.out.println("le info sono essuno: " + kr.getSitePassword("facebook"));
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | IOException | ClassNotFoundException | BadPaddingException e) {
			e.printStackTrace();
			//System.out.println("errore: "+e.getMessage());
		}
	}

}
