package progetto3;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.sql.Timestamp;
import java.util.ArrayList;


public class TSA {
	final static String PATH = Paths.get(System.getProperty("user.dir")).toString();
	final static String FILE_NAME = PATH + "/data/rootHashValues";
	final static int TREE_ELEM = 8;
	final static String DUMMY_HASH_ALG = "SHA-1";

	private long serialNumber;
	private Signature sig;
	// fai un bel Arraylist co sti cosi
	private ArrayList<byte[]> hashTreeValues;
	//   | h_12 | h_34 | h_56 | h_78 | h_14 | h_58 | h_18 |


	public TSA(PrivateKey keySig) throws NoSuchAlgorithmException, InvalidKeyException {
		serialNumber = 0;
		sig = Signature.getInstance("SHA1withDSA");
		sig.initSign(keySig);

		hashTreeValues = new ArrayList<byte[]>();
	}

	public ArrayList<Marca> metodo(ArrayList<Richiesta> requests) throws NoSuchAlgorithmException, SignatureException, IOException{
		//IN REALTA' LE RICHIESTE DEVONO ARRIVARE CIFRATE
		
		ArrayList<Marca> marche = new ArrayList<Marca>();
		ArrayList<TempBox> linkedInformation = new ArrayList<TempBox>();

		// FAI REQUEST MULTIPLA DI 8 CON PADDING FITTIZZZI 
		// genera a caso un array di byte di grandezza corretta
		int remain = requests.size() % TREE_ELEM;

		if(remain != 0) {
			// aggiungi nodi fittizi
			for(int i = remain; i < TREE_ELEM; i++) {
				byte [] dummyHash = getDummyHash();
				requests.add(new Richiesta("defUser", dummyHash));
			}
		}

		ArrayList<ArrayList<Richiesta>> splittedRequest = new ArrayList<ArrayList<Richiesta>>();

		for(int i = 0; i<requests.size(); i+=8) {
			splittedRequest.add(new ArrayList<Richiesta> (requests.subList(i, i+8)));
		}

		for(ArrayList<Richiesta> r : splittedRequest) {
			// otteniamo il rootHashValue
			byte[] rootHashValue = computeTree(r);

			// data e ora
			long time = getTime();

			// pubblica il root value
			writeRootValue(time, rootHashValue);

			// creiamo le marche per l'albero
			for(int i = 0; i<8; i++) {
				// firmare TUTTA la info
				sig.update(concatenate(r.get(i).getH(), longToBytes(time)));

				if(i%2==0) {
					linkedInformation.add(new TempBox(r.get(i+1).getH(), true));				
				}else {
					linkedInformation.add(new TempBox(r.get(i-1).getH(), false));
				}
				if(i<4) {
					if(i<2) {
						//add 34
						linkedInformation.add(new TempBox(hashTreeValues.get(1), true));
					}else {
						//add 12
						linkedInformation.add(new TempBox(hashTreeValues.get(0), false));
					}
					//add h58
					linkedInformation.add(new TempBox(hashTreeValues.get(5), true));

				} else {
					if(i<6) {
						//add 78
						linkedInformation.add(new TempBox(hashTreeValues.get(3), true));
					}else {
						//add 56
						linkedInformation.add(new TempBox(hashTreeValues.get(2), true));
					}
					//add 14
					linkedInformation.add(new TempBox(hashTreeValues.get(4), false));
				}

				marche.add(new Marca(r.get(i).getIdUser(), serialNumber++, time, r.get(i).getH(), sig.sign(), linkedInformation));

			}

		}

		return marche;

	}

	private byte[] getDummyHash() throws NoSuchAlgorithmException {
		// oppure genero direttamente un array di byte casuali?
		SecureRandom random = new SecureRandom();
		byte inputBytes[] = new byte[1024];
		random.nextBytes(inputBytes);

		MessageDigest digest = MessageDigest.getInstance(DUMMY_HASH_ALG);

		return digest.digest(inputBytes);
	}

	private byte[] longToBytes(long n) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(n);
		return buffer.array();
	}

	private byte[] computeTree(ArrayList<Richiesta> requests) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");

		for(int i = 0; i < TREE_ELEM; i+=2) {
			md.update(concatenate(requests.get(i).getH(), requests.get(i+1).getH()));
			hashTreeValues.add(md.digest());
		}

		md.update(concatenate(hashTreeValues.get(0), hashTreeValues.get(1)));
		hashTreeValues.add(md.digest());

		md.update(concatenate(hashTreeValues.get(2), hashTreeValues.get(3)));
		hashTreeValues.add(md.digest());

		md.update(concatenate(hashTreeValues.get(4), hashTreeValues.get(5)));
		hashTreeValues.add(md.digest());// Root Hash Value

		return hashTreeValues.get(6);

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

	private void writeRootValue(long time, byte[] rootHashValue) throws IOException {
		// scriviamo il root hash value nel file
		File rootHashFile = new File(FILE_NAME);
		FileWriter writer = new FileWriter (rootHashFile);

		writer.write((int) time);
		writer.write("\n");
		writer.write(String.format( "%064x", new BigInteger( 1, rootHashValue ) ));
		writer.write("\n");

		writer.flush();
		writer.close();
	}
}
