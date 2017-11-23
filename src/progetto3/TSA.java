package progetto3;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;

public class TSA {
	private long serialNumber;
	private Signature sig;
	private byte[] h_12;
	private byte[] h_34;
	private byte[] h_56;
	private byte[] h_78;
	private byte[] h_14;
	private byte[] h_58;
	private byte[] h_18;
	
	public TSA(PrivateKey keySig) throws NoSuchAlgorithmException, InvalidKeyException {
		serialNumber = 0;
		sig = Signature.getInstance("SHA1withDSA");
		sig.initSign(keySig);
	}

	public ArrayList<Marca> metodo(ArrayList<Richiesta> requests) throws NoSuchAlgorithmException, SignatureException{
		int numReq = 0;
		Marca m1, m2, m3, m4, m5, m6, m7, m8;
		ArrayList<Marca> marche = new ArrayList<Marca>();
		
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
			
			// data e ora
			long time = getTime();
			
			// creiamo le marche per l'albero
			for(int i = 0; i<8; i++) {
				// firmare TUTTA la info
				sig.update(concatenate(r.get(i).getH(), longToBytes(time)));
				marche.add(new Marca(r.get(i).getIdUser(), serialNumber++, time, r.get(i).getH(), sig.sign()));
				if(i%2==0) {
					//add r(i+1)					
				}else {
					//add r(i-1)
				}
				if(i<4) {
					//add h58
					if(i<2) {
						//add 34
					}else {
						//add 12
					}
					
				} else {
					//add 14
					if(i<6) {
						//add 78
					}else {
						//add 56
					}
				}
				
			}
			
		}
		
		return marche;
	
	}
	
	private byte[] longToBytes(long n) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(n);
		return buffer.array();
	}
	
	private byte[] computeTree(ArrayList<Richiesta> requests) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		md.update(concatenate(requests.get(0).getH(), requests.get(1).getH()));
		h_12 = md.digest();
		
		md.update(concatenate(requests.get(2).getH(), requests.get(3).getH()));
		h_34 = md.digest();
		
		md.update(concatenate(requests.get(4).getH(), requests.get(5).getH()));
		h_56 = md.digest();
		
		md.update(concatenate(requests.get(6).getH(), requests.get(7).getH()));
		h_78 = md.digest();
		
		md.update(concatenate(h_12, h_34));
		h_14 = md.digest();

		md.update(concatenate(h_56, h_78));
		h_58 = md.digest();
		
		md.update(concatenate(h_14, h_58));
		h_18 = md.digest(); // Root Hash Value
		
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
