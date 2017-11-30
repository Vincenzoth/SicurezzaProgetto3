package progetto3;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.sql.Date;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;


public class TSA {
	final static String PATH = Paths.get(System.getProperty("user.dir")).toString();
	final static String FILE_NAME_ROOTH = PATH + "/data/rootHashValues";
	final static String FILE_NAME_SUPERH = PATH + "/data/superHashValues";
	final static String PATH_FILE_MARCHE = PATH + "/data/marche/";
	final static int TREE_ELEM = 8;
	final static String DUMMY_HASH_ALG = "SHA-1";
	final static String TREE_HASH_ALG = "SHA-256";
	final static String SUPER_HASH_ALG = "SHA-256";
	final static String CIPHER_MODE = "RSA/CBC/PKCS5Padding"; 

	private long serialNumber;
	private Signature sig;
	private String algorithmSignature;
	private String previusSHV;
	private Cipher cipher;
	private ArrayList<byte[]> hashTreeValues;
	//   | h_12 | h_34 | h_56 | h_78 | h_14 | h_58 | h_18 |


	/**
	 * Costruttore della classe 
	 * @param keySig chiave per la firma della marca
	 * @param algorithmSignature tipo di algoritmo utilizzato per la firma della marca
	 * @param keyCod chiave per decifrare le richieste 
	 * @param algorithmCipher tipo di algoritmo usato per la decifratura delle richieste 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 */
	public TSA(PrivateKey keySig, String algorithmSignature, PrivateKey keyCod, String algorithmCipher) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
		serialNumber = 0;
		this.algorithmSignature = algorithmSignature;
		sig = Signature.getInstance(this.algorithmSignature);
		sig.initSign(keySig);

		hashTreeValues = new ArrayList<byte[]>();

		File path = new File(PATH_FILE_MARCHE);
		if(!path.exists()) { 			 
			path.mkdirs();
		}
		cipher = Cipher.getInstance(algorithmCipher);
		cipher.init( Cipher.DECRYPT_MODE, keyCod);

	}


	/**
	 * Metodo che genera le marche a partire dalle richieste passate come parametro 
	 * @param cipherRequests array list che continete le richieste cifrate 
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public  void generateMarche(ArrayList<SealedObject> cipherRequests) throws NoSuchAlgorithmException, SignatureException, IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException{

		ArrayList<Request> requests = new  ArrayList<Request>();
		for (SealedObject req : cipherRequests) 
			requests.add((Request)req.getObject(this.cipher));


		ArrayList<LinkedInfoUnit> linkedInformation = new ArrayList<LinkedInfoUnit>();

		// genera a caso un array di byte di grandezza corretta
		int remain = requests.size() % TREE_ELEM;

		if(remain != 0) {
			// aggiungi nodi fittizi
			for(int i = remain; i < TREE_ELEM; i++) {
				byte [] dummyHash = getDummyHash();
				requests.add(new Request("defUser", dummyHash));
			}
		}

		ArrayList<ArrayList<Request>> splittedRequest = new ArrayList<ArrayList<Request>>();

		for(int i = 0; i<requests.size(); i+=8) {
			splittedRequest.add(new ArrayList<Request> (requests.subList(i, i+8)));
		}

		for(ArrayList<Request> r : splittedRequest) {
			// otteniamo il rootHashValue
			byte[] rootHashValue = computeTree(r);

			// data e ora
			long time = getTime();

			// pubblica il root value
			writeRootValue(time, rootHashValue);

			// calcolo SuperHashVAlue
			byte[] superHashValue = computeSuperHashValue(rootHashValue);
			
			// pubblica il root value
			writeSuperHashValue(time, superHashValue);

			// creiamo le marche per l'albero
			for(int i = 0; i<8; i++) {
				if(!linkedInformation.isEmpty())
					linkedInformation.clear();

				if(i%2==0) {
					linkedInformation.add(new LinkedInfoUnit(r.get(i+1).getH(), true));				
				}else {
					linkedInformation.add(new LinkedInfoUnit(r.get(i-1).getH(), false));
				}
				if(i<4) {
					if(i<2) {
						//add 34
						linkedInformation.add(new LinkedInfoUnit(hashTreeValues.get(1), true));
					}else {
						//add 12
						linkedInformation.add(new LinkedInfoUnit(hashTreeValues.get(0), false));
					}
					//add h58
					linkedInformation.add(new LinkedInfoUnit(hashTreeValues.get(5), true));

				} else {
					if(i<6) {
						//add 78
						linkedInformation.add(new LinkedInfoUnit(hashTreeValues.get(3), true));
					}else {
						//add 56
						linkedInformation.add(new LinkedInfoUnit(hashTreeValues.get(2), true));
					}
					//add 14
					linkedInformation.add(new LinkedInfoUnit(hashTreeValues.get(4), false));
				}

				Marca m = new Marca(r.get(i).getIdUser(), serialNumber++, time, r.get(i).getH(), 
						byteArrayToHexString(rootHashValue), previusSHV , byteArrayToHexString(superHashValue) , linkedInformation, this.algorithmSignature,TREE_HASH_ALG, SUPER_HASH_ALG);

				writeMarca(m);
			}
		}
	}

	/**
	 * metodo per generare difest fittizi
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private byte[] getDummyHash() throws NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		byte inputBytes[] = new byte[1024];
		random.nextBytes(inputBytes);

		MessageDigest digest = MessageDigest.getInstance(DUMMY_HASH_ALG);

		return digest.digest(inputBytes);
	}
	
	/**
	 * Metodo per generare un IV hash per inizializzare la catena di Super Hash Value
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private byte[] generateIV() throws NoSuchAlgorithmException {
		SecureRandom random = new SecureRandom();
		byte inputBytes[] = new byte[1024];
		random.nextBytes(inputBytes);

		MessageDigest digest = MessageDigest.getInstance(SUPER_HASH_ALG);

		return digest.digest(inputBytes);
	}

	/**
	 * Metodo di supporto per convertire un long in un array di byte
	 * @param n long da convertire 
	 * @return long convertito in array di byte
	 */
	private byte[] longToBytes(long n) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(n);
		return buffer.array();
	}

	/**
	 * Metdodo che crea il Merkel tree a partire dalle otto richieste passata come parametro 
	 * @param requests array list di richieste (otto richieste)
	 * @return ritorna il root hash value
	 * @throws NoSuchAlgorithmException
	 */
	private byte[] computeTree(ArrayList<Request> requests) throws NoSuchAlgorithmException {
		if(!hashTreeValues.isEmpty())
			hashTreeValues.clear();

		MessageDigest md = MessageDigest.getInstance(TREE_HASH_ALG);

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
	
	/**
	 * Metodo che genera il Super Hash Value s partire da un Root Hash
	 * @param rootHashValue root Hash value
	 * @return l'array di byte del super hash value
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	private byte[] computeSuperHashValue(byte[] rootHashValue) throws NoSuchAlgorithmException, IOException {
		MessageDigest md = MessageDigest.getInstance(SUPER_HASH_ALG);

		// scrivi i file della chiave
		File superHValue = new File(FILE_NAME_SUPERH);
		if(!superHValue.exists()) { 
			// crea il file dei SHV e inizializzalo con IV
			String IV = byteArrayToHexString(generateIV());
			FileWriter writer = new FileWriter (superHValue);
			writer.write("initial Super Hash:\n");
			writer.write(IV);
			writer.write("\n\n");
			writer.close();

			previusSHV = IV;
		}else {
			//Leggi l'ultimo SHV - è quello in coda al file
			BufferedReader br = new BufferedReader(new FileReader(superHValue));

			while(br.readLine() != null) {
				previusSHV = br.readLine();
				br.readLine();
			}
			
			br.close();
		}

		md.update(concatenate(hexStringToByteArray(previusSHV), rootHashValue));
		return md.digest();
	}

	/**
	 * Metodo di supporto per concatenare due array di byte 
	 * @param first primo array di byte 
	 * @param second sencondo array di byte 
	 * @return
	 */
	private byte[] concatenate(byte[] first, byte[] second) {
		byte[] full = new byte[first.length + second.length];
		System.arraycopy(first, 0, full, 0, first.length);
		System.arraycopy(second, 0, full, first.length, second.length);

		return full;
	}

	/**
	 * Metodo di supporto che restituisce la data e l'ora necessaria per la marca temporale
	 * @return data e ora nel formato definito dalla classe Timestamp
	 */
	private long getTime() {
		java.util.Date date = new java.util.Date();
		return new Timestamp(date.getTime()).getTime();
	}

	/**
	 * Metodo di supporto che scrive la marca temporale generata in un file 
	 * @param m marca temporale
	 * @throws IOException
	 * @throws SignatureException
	 */
	@SuppressWarnings("unchecked")
	private void writeMarca(Marca m) throws IOException, SignatureException {
		JSONObject marca = new JSONObject();
		JSONArray  linkInfo = new JSONArray ();

		for(LinkedInfoUnit liu : m.getLinkedInformation()) {
			JSONObject linkingUnit = new JSONObject();
			linkingUnit.put("hash", byteArrayToHexString(liu.getH()));
			linkingUnit.put("right", liu.isR());
			linkInfo.add(linkingUnit);
		}

		Date date = new Date(m.getTime());
		DateFormat formatter = new SimpleDateFormat("dd-MM-YYYY_HH:mm:ss:SSS");
		String dateFormatted = formatter.format(date);
		formatter = new SimpleDateFormat("dd-MM-YYYY_HH-mm-ss-SSS");
		String dateFormattedToFile = formatter.format(date);

		marca.put("idUser", m.getIdUser());
		marca.put("serialNumber", m.getSerialNumber());
		marca.put("timestamp", m.getTime());
		marca.put("time", dateFormatted);
		marca.put("rootHashValue", m.getRootHashValue());
		marca.put("superHashValue_pre", m.getSuperHV_prev());
		marca.put("superHashValue", m.getSuperHV());
		marca.put("digest", byteArrayToHexString(m.getDigest()));
		marca.put("linkedInformation", linkInfo);
		marca.put("algorithmSignature", this.algorithmSignature );
		marca.put("algorithmHashTree", TREE_HASH_ALG );
		marca.put("algorithmHashSuper", SUPER_HASH_ALG );

		// Firma
		sig.update(marca.toJSONString().getBytes("UTF8"));
		byte[] signat = sig.sign();

		FileOutputStream writer = 	new FileOutputStream(PATH_FILE_MARCHE + m.getSerialNumber() + "_" + m.getIdUser() + "_" + dateFormattedToFile+".tms");   
		writer.write(signat);
		writer.write(marca.toJSONString().toString().getBytes());
		writer.flush();
		writer.close();
	}

	/**
	 * Metodo per la scrittura del Root value nel file  per renderlo pubblico 
	 * @param time tempo di pubblicazione 
	 * @param rootHashValue root hash value 
	 * @throws IOException
	 */
	private void writeRootValue(long time, byte[] rootHashValue) throws IOException {
		// scriviamo il root hash value nel file
		File rootHashFile = new File(FILE_NAME_ROOTH);
		FileWriter writer = new FileWriter (rootHashFile, true);

		Date date = new Date(time);
		DateFormat formatter = new SimpleDateFormat("dd/MM/YYYY  -  HH:mm:ss:SSS");
		String dateFormatted = formatter.format(date);

		writer.write( "Root Hash : " + dateFormatted);
		//writer.write("\n");
		//writer.write(Base64.getEncoder().encodeToString(rootHashValue));
		writer.write("\n");
		writer.write(byteArrayToHexString(rootHashValue));
		writer.write("\n\n");

		writer.flush();
		writer.close();
	}
	
	/**
	 * Metodo per la scrittura del SUper Hash value nel file  per renderlo pubblico 
	 * @param superHashValue super hash value 
	 * @throws IOException
	 */
	private void writeSuperHashValue(long time, byte[] superHashValue) throws IOException {
		File superHashFile = new File(FILE_NAME_SUPERH);
		FileWriter writer = new FileWriter (superHashFile, true);
		
		Date date = new Date(time);
		DateFormat formatter = new SimpleDateFormat("dd/MM/YYYY  -  HH:mm:ss:SSS");
		String dateFormatted = formatter.format(date);

		writer.write( "Super Hash : " + dateFormatted);
		
		writer.write("\n");
		writer.write(byteArrayToHexString(superHashValue));
		writer.write("\n\n");
		writer.flush();
		writer.close();
	}

	private String byteArrayToHexString(byte[] arrayBytes) {
		StringBuffer stringBuffer = new StringBuffer();
		for (int i = 0; i < arrayBytes.length; i++) {
			stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return stringBuffer.toString();
	}

	private byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}
}
