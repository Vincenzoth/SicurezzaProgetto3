package progetto3;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;

public class TSA {
	private long serialNumber;
	private Signature sig;
	
	public TSA(PrivateKey keySig) throws NoSuchAlgorithmException, InvalidKeyException {
		serialNumber = 0;
		sig = Signature.getInstance("SHA1withDSA");
		sig.initSign(keySig);
	}

	public ArrayList<Marca> metodo(ArrayList<Richiesta> requests) throws NoSuchAlgorithmException{
		int numReq = 0;
		
		// FAI REQUEST MULTIPLA DI 8 CON PADDING FITTIZZZI 
		
		ArrayList<ArrayList<Richiesta>> splittedRequest = new ArrayList<ArrayList<Richiesta>>();
		
		for(int i = 0; i<requests.size(); i+=8) {
			splittedRequest.add(new ArrayList<Richiesta> (requests.subList(i, i+8)));
		}
		
		for(ArrayList<Richiesta> r : splittedRequest) {
			// otteniamo il rootHashValue
			byte[] rootHashValue = computeTree(r);
			// pubblica il root value
			// writeRootValue();
			
			// costruiamo le marche
			
			// data e ora
			long time = getTime();
			
			// creiamo le marche per l'albero
		
			sig.update(concatenate(r.get(0).getH(), time));
			signatureBytes = sig.sign();
			
			Marca m1 = new Marca(r.get(0).getIdUser(), serialNumber++, t, r.get(0).getH(), new byte[2]);
			
		}
	
	}
	
	private byte[] computeTree(ArrayList<Richiesta> requests) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		md.update(concatenate(requests.get(0).getH(), requests.get(1).getH()));
		byte[] h_12 = md.digest();
		
		md.update(concatenate(requests.get(2).getH(), requests.get(3).getH()));
		byte[] h_34 = md.digest();
		
		md.update(concatenate(requests.get(4).getH(), requests.get(5).getH()));
		byte[] h_56 = md.digest();
		
		md.update(concatenate(requests.get(6).getH(), requests.get(7).getH()));
		byte[] h_78 = md.digest();
		
		md.update(concatenate(h_12, h_34));
		byte[] h_14 = md.digest();

		md.update(concatenate(h_56, h_78));
		byte[] h_58 = md.digest();
		
		md.update(concatenate(h_14, h_58));
		byte[] h_18 = md.digest(); // Root Hash Value
		
		return h_18;

	}
	
	private byte[] concatenate(byte[] first, byte[] second) {
		byte[] full = new byte[first.length + second.length];
		System.arraycopy(first, 0, full, 0, first.length);
		System.arraycopy(second, 0, full, first.length, second.length);
		
		return full;
	}
	
	private long getTime() {
		java.util.Date date = new java.util.Date();
		return new Timestamp(date.getTime()).getTime();
	}
}
