package progetto3;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
	private MessageDigest md;
	private Signature sig;
	private PublicKey keySig;

	/**
	 * Costruttore della classe 
	 * @param hashAlghoritm Tipo da algoritmo utilizzato per l'hash
	 * @param keySig chiave pubblica  per la firma 
	 * @throws NoSuchAlgorithmException
	 */
	public Validator(String hashAlghoritm, PublicKey keySig) throws NoSuchAlgorithmException {
		this.md = MessageDigest.getInstance(hashAlghoritm);
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
	public boolean check(String marcaPath, byte[] myDigest) throws FileNotFoundException, IOException, ParseException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, MyException {
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
		sig = Signature.getInstance(marca.getAlgorithSignature()); // se lo prendo dalla marca il tipo di firma?
		Boolean verified;
		sig.initVerify(keySig);
		sig.update(marcaJSON.getBytes("UTF8"));

		try {
			verified = sig.verify(signatureBytes);
		} catch (SignatureException e) {
			verified = false;
		}


		// calcolo root hash value a partire dal proprio digest
		byte[] currentDigest = myDigest;

		for(LinkedInfoUnit li: marca.getLinkedInformation()) {

			if(li.isR()) {
				// Concatenare a destra
				md.update(concatenate(currentDigest, li.getH()));
			}else {
				/// Concatenare a sinistra
				md.update(concatenate(li.getH(),currentDigest));
			}

			currentDigest = md.digest();
		}

		String computedRootHash = String.format( "%064x", new BigInteger( 1, currentDigest ) );

		if(computedRootHash.equals(marca.getRootHashValue()))
			returnValue = true;
		else
			returnValue = false;
		
		
		if(!verified)
			throw new MyException("Firma non valida!  RoothashValue: " + returnValue);

		return returnValue;
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
				marcaJSON.get("algorithmSignature").toString());
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
