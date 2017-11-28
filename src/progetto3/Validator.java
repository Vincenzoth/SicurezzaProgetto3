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

	public Validator(String hashAlghoritm, PublicKey keySig) throws NoSuchAlgorithmException {
		this.md = MessageDigest.getInstance(hashAlghoritm);
		this.keySig = keySig;
	}


	public boolean check(String marcaPath, byte[] myDigest, String rootHashValue) throws FileNotFoundException, IOException, ParseException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, MyException {
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


		// Verifica della firma
		sig = Signature.getInstance("SHA1withDSA"); // se lo prendo dalla marca il tipo di firma?
		Boolean verified;
		sig.initVerify(keySig);
		sig.update(marcaJSON.getBytes("UTF8"));

		try {
			verified = sig.verify(signatureBytes);
		} catch (SignatureException e) {
			verified = false;
		}


		Marca marca = readMarca(marcaJSON);

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

		System.out.println(computedRootHash);


		if(computedRootHash.equals(rootHashValue))
			returnValue = true;
		else
			returnValue = false;
		
		
		if(!verified)
			throw new MyException("Firma non valida!  RoothashValue: " + returnValue);

		return returnValue;
	}

	private Marca readMarca(String marcaString) throws FileNotFoundException, IOException, ParseException {
		JSONParser parser = new JSONParser();
		JSONObject marcaJSON = (JSONObject) parser.parse(marcaString);

		System.out.println(marcaJSON.get("idUser"));

		JSONArray  linkedInformationJSON = (JSONArray) marcaJSON.get("linkedInformation");

		ArrayList<LinkedInfoUnit> linkedInformation = new ArrayList<LinkedInfoUnit>();

		for(int i = 0; i < linkedInformationJSON.size(); i++) {
			JSONObject linkUnitJSON = (JSONObject) parser.parse(linkedInformationJSON.get(i).toString());			
			linkedInformation.add(new LinkedInfoUnit(hexStringToByteArray(linkUnitJSON.get("hash").toString()), (boolean) linkUnitJSON.get("right")));
		}

		return new Marca(marcaJSON.get("idUser").toString(),
				(long) marcaJSON.get("serialNumber"),
				(long) marcaJSON.get("timest"),
				hexStringToByteArray(marcaJSON.get("digest").toString()),
				linkedInformation
				);
	}

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
