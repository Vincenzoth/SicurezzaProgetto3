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
	public Validator(String hashAlghoritmRoot, String hashAlghoritmSuper, PublicKey keySig) throws NoSuchAlgorithmException {
		this.mdRoot = MessageDigest.getInstance(hashAlghoritmRoot);
		this.mdSuper = MessageDigest.getInstance(hashAlghoritmSuper);
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
	 * 
	 * @param marcaPath
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
	 * 
	 * @param pathFileRootHashValue
	 * @param pathFileSuperHashValue
	 * @return
	 * @throws IOException
	 * @throws MyException
	 */
	public boolean checkSuperHashList(String pathFileRootHashValue, String pathFileSuperHashValue) throws IOException, MyException {
		File fileRHV = new File(pathFileRootHashValue);
		File fileSHV = new File(pathFileSuperHashValue);
		
		BufferedReader  readerRHV = new BufferedReader(new FileReader(fileRHV));
		BufferedReader  readerSHV = new BufferedReader(new FileReader(fileSHV));
		
		String lineSHV_prev = readerSHV.readLine();
		String lineSHV;
		String lineRHV;
		byte[] computedSHV;
		boolean isHashValid;
		while((lineSHV = readerSHV.readLine()) != null) {
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
			

			lineSHV_prev = lineSHV;
		}
		readerSHV.close();
		readerRHV.close();
		
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
	
	private String byteArrayToHexString(byte[] arrayBytes) {
		StringBuffer stringBuffer = new StringBuffer();
		for (int i = 0; i < arrayBytes.length; i++) {
			stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return stringBuffer.toString();
	}
}
