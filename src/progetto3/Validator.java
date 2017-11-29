package progetto3;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Validator {
	private MessageDigest mdRoot;
	private MessageDigest mdSuper;
	private Signature sig;
	private PublicKey keySig;

	/**
	 * Costruttore della classe 
	 * @param hashAlghoritm Tipo da algoritmo utilizzato per l'hash
	 * @param keySig chiave pubblica  per la firma 
	 * @throws NoSuchAlgorithmException
	 */
	public Validator(PublicKey keySig) throws NoSuchAlgorithmException {
		this.keySig = keySig;
	}


	/**
	 * Metodo per la verifica della marca 
	 * @param marcaPath percorso del file che continene la marca
	 * @param myDigest digest usato  per il  calcolo del root hash value 
	 * @param rootHashValue root hash value noto usato per la verifica 
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws ParseException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws MyException
	 */
	public boolean checkRootHash(String marcaPath, byte[] myDigest) throws FileNotFoundException, IOException, ParseException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, MyException {
		boolean returnValue;

		// VERIFICARE LA FIRMA
		FileInputStream fis = new FileInputStream(new File(marcaPath));
		byte[] signatureBytes = null;

		byte[] firtBytesSig = new byte[2];
		fis.read(firtBytesSig);
		int remainingByte = firtBytesSig[1];
		byte[] otherBytesSig = new byte[remainingByte];
		fis.read(otherBytesSig);
		signatureBytes = new byte[2 + remainingByte];
		System.arraycopy(firtBytesSig, 0, signatureBytes, 0, 2);
		System.arraycopy(otherBytesSig, 0, signatureBytes, 2, remainingByte);

		String marcaJSON = "";
		int content;
		while ((content = fis.read()) != -1) {
			marcaJSON = marcaJSON + (char) content;
		}

		fis.close();

		Marca marca = readMarca(marcaJSON);
		// Verifica della firma
		sig = Signature.getInstance(marca.getAlgorithSignature());
		Boolean verified;
		sig.initVerify(keySig);
		sig.update(marcaJSON.getBytes("UTF8"));

		try {
			verified = sig.verify(signatureBytes);
		} catch (SignatureException e) {
			verified = false;
		}

		this.mdRoot = MessageDigest.getInstance(marca.getAlgorithmHashTree());
		// calcolo root hash value a partire dal proprio digest
		byte[] currentDigest = myDigest;

		for(LinkedInfoUnit li: marca.getLinkedInformation()) {

			if(li.isR()) {
				// Concatenare a destra
				mdRoot.update(concatenate(currentDigest, li.getH()));
			}else {
				/// Concatenare a sinistra
				mdRoot.update(concatenate(li.getH(),currentDigest));
			}

			currentDigest = mdRoot.digest();
		}

		String computedRootHash = String.format( "%064x", new BigInteger( 1, currentDigest ) );

		if(computedRootHash.equals(marca.getRootHashValue()))
			returnValue = true;
		else
			returnValue = false;


		if(!verified) {
			String mesg = returnValue ? "Firma Non valida!  Root Hash Value valido!" : "Firma Non valida!  Root Hash Value NON valido!";
			throw new MyException(mesg);
		}

		return returnValue;
	}

	/**
	 * IL metodo valuta la validità del super hash value della marca temporale passata come parametro
	 * 
	 * @param marcaPath path del file della marca temporale da validare
	 * @return
	 * @throws IOException
	 * @throws ParseException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws MyException
	 */
	public boolean checkSuperHash(String marcaPath) throws IOException, ParseException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, MyException {
		// leggere la marca dal file
		FileInputStream fis = new FileInputStream(new File(marcaPath));
		byte[] signatureBytes;
		byte[] firtBytesSig = new byte[2];
		fis.read(firtBytesSig);
		int remainingByte = firtBytesSig[1];
		byte[] otherBytesSig = new byte[remainingByte];
		fis.read(otherBytesSig);
		signatureBytes = new byte[2 + remainingByte];
		System.arraycopy(firtBytesSig, 0, signatureBytes, 0, 2);
		System.arraycopy(otherBytesSig, 0, signatureBytes, 2, remainingByte);


		String marcaJSON = "";
		int content;
		while ((content = fis.read()) != -1) {
			marcaJSON = marcaJSON + (char) content;
		}

		fis.close();

		Marca marca = readMarca(marcaJSON);
		sig = Signature.getInstance(marca.getAlgorithSignature());
		Boolean verified;
		sig.initVerify(keySig);
		sig.update(marcaJSON.getBytes("UTF8"));

		try {
			verified = sig.verify(signatureBytes);
		} catch (SignatureException e) {
			verified = false;
		}
		
		this.mdSuper = MessageDigest.getInstance(marca.getAlgorithHashSuper());


		mdSuper.update(concatenate(
				hexStringToByteArray(marca.getSuperHV_prev()),
				hexStringToByteArray(marca.getRootHashValue()))
				);
		byte[] computedSHV = mdSuper.digest();

		boolean returnValue = byteArrayToHexString(computedSHV).equals(marca.getSuperHV());

		if(!verified) {
			String mesg = returnValue ? "Firma Non valida!  Super Hash Value valido!" : "Firma Non valida!  Super Hash Value NON valido!";
			throw new MyException(mesg);
		}

		return returnValue;
	}

	/**
	 * Il metodo valuta la validità della catena di superHash value, e valuta se la marca passata come parametro appartiene alla catena
	 * 
	 * @param marcaPath path del file della marca da testare
	 * @param pathFileRootHashValue path del file dei Root HAsh Values
	 * @param pathFileSuperHashValue path del file dei Super HAsh Values
	 * @return
	 * @throws IOException
	 * @throws MyException
	 * @throws ParseException 
	 * @throws NoSuchAlgorithmException 
	 */
	public boolean checkSuperHashList(String marcaPath, String pathFileRootHashValue, String pathFileSuperHashValue) throws IOException, MyException, ParseException, NoSuchAlgorithmException {
		// leggere la marca dal file
		FileInputStream fis = new FileInputStream(new File(marcaPath));
		byte[] firtBytesSig = new byte[2];
		fis.read(firtBytesSig);
		int remainingByte = firtBytesSig[1];
		byte[] otherBytesSig = new byte[remainingByte];
		fis.read(otherBytesSig);

		String marcaJSON = "";
		int content;
		while ((content = fis.read()) != -1) {
			marcaJSON = marcaJSON + (char) content;
		}

		fis.close();

		Marca marca = readMarca(marcaJSON);
		this.mdSuper = MessageDigest.getInstance(marca.getAlgorithHashSuper());

		// leggi i file pubblici dei SuperHash e dei RootHash
		boolean rootInChain = false;
		File fileRHV = new File(pathFileRootHashValue);
		File fileSHV = new File(pathFileSuperHashValue);

		BufferedReader  readerRHV = new BufferedReader(new FileReader(fileRHV));
		BufferedReader  readerSHV = new BufferedReader(new FileReader(fileSHV));

		// leggi Super Hash Value Iniziale
		readerSHV.readLine();
		String lineSHV_prev = readerSHV.readLine();
		readerSHV.readLine();

		String lineSHV;
		String lineRHV;
		byte[] computedSHV;
		boolean isHashValid;
		while(readerSHV.readLine() != null) {
			lineSHV = readerSHV.readLine();
			readerSHV.readLine();

			readerRHV.readLine();
			lineRHV = readerRHV.readLine();
			readerRHV.readLine();

			//Valutare bontà catena
			mdSuper.update(concatenate(
					hexStringToByteArray(lineSHV_prev),
					hexStringToByteArray(lineRHV))
					);
			computedSHV = mdSuper.digest();

			isHashValid = byteArrayToHexString(computedSHV).equals(lineSHV);

			if(!isHashValid) {
				readerSHV.close();
				readerRHV.close();				
				throw new MyException("La catena di Super Hash Value Non è valida!");
			}

			// controllo se il RootHAsh della marca è presente nella catena
			if(lineRHV.equals(marca.getRootHashValue()))
				rootInChain = true; 

			lineSHV_prev = lineSHV;
		}
		readerSHV.close();
		readerRHV.close();
		
		if(!rootInChain)
			throw new MyException("La catena di Super Hash Value è valida, ma il Root Hash della marca non è contenuto nella catena!!");

		return true;
	}

	/**
	 * Metodo che legge e restituisce la marca temporale a partire dalla struttura dati 
	 * in JSON contenuta nel file 
	 * @param marcaString
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws ParseException
	 */
	private Marca readMarca(String marcaString) throws FileNotFoundException, IOException, ParseException {
		JSONParser parser = new JSONParser();
		JSONObject marcaJSON = (JSONObject) parser.parse(marcaString);

		JSONArray  linkedInformationJSON = (JSONArray) marcaJSON.get("linkedInformation");

		ArrayList<LinkedInfoUnit> linkedInformation = new ArrayList<LinkedInfoUnit>();

		for(int i = 0; i < linkedInformationJSON.size(); i++) {
			JSONObject linkUnitJSON = (JSONObject) parser.parse(linkedInformationJSON.get(i).toString());			
			linkedInformation.add(new LinkedInfoUnit(hexStringToByteArray(linkUnitJSON.get("hash").toString()), (boolean) linkUnitJSON.get("right")));
		}

		return new Marca(marcaJSON.get("idUser").toString(),
				(long) marcaJSON.get("serialNumber"),
				(long) marcaJSON.get("timestamp"),
				hexStringToByteArray(marcaJSON.get("digest").toString()),
				marcaJSON.get("rootHashValue").toString(),
				marcaJSON.get("superHashValue_pre").toString(),
				marcaJSON.get("superHashValue").toString(),				
				linkedInformation,
				marcaJSON.get("algorithmSignature").toString(),
				marcaJSON.get("algorithmHashTree").toString(),
				marcaJSON.get("algorithmHashSuper").toString()				
				);
	}

	/**
	 * Metodo di supporto che concatena due array di byte 
	 * @param first primo array di byte 
	 * @param second secondo array di byte
	 * @return
	 */
	private byte[] concatenate(byte[] first, byte[] second) {
		byte[] full = new byte[first.length + second.length];
		System.arraycopy(first, 0, full, 0, first.length);
		System.arraycopy(second, 0, full, first.length, second.length);

		return full;
	}

	/**
	 * Il metodo converte una stringa di valori esadecimali in un array di byte
	 * @param s Stringa di valori esadecimali
	 * @return array di byte convertito
	 */
	private byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	/**
	 * Il metodo converte in un array di byte in una stringa di valori esadecimali
	 * @param arrayBytes array di byte da convertire
	 * @return stringa di valori esadecimali
	 */
	private String byteArrayToHexString(byte[] arrayBytes) {
		StringBuffer stringBuffer = new StringBuffer();
		for (int i = 0; i < arrayBytes.length; i++) {
			stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return stringBuffer.toString();
	}
}
