package progetto3;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Validator {
	private MessageDigest md;

	public Validator(String hashAlghoritm) throws NoSuchAlgorithmException {
		this.md = MessageDigest.getInstance(hashAlghoritm);
	}


	public boolean check(String marcaPath, byte[] myDigest, String rootHashValue) throws FileNotFoundException, IOException, ParseException {
		
		Marca marca = readMarca(marcaPath);

		// VERIFICARE LA FIRMA

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
		
		if(computedRootHash.equals(rootHashValue)) {
			System.out.println("Tappost!");
		}else
			System.out.println("niente!");
			
		
		return true;
	}
	
	private Marca readMarca(String marcaPath) throws FileNotFoundException, IOException, ParseException {
		JSONParser parser = new JSONParser();
		JSONObject marcaJSON = (JSONObject) parser.parse(new FileReader(marcaPath));
		
		System.out.println(marcaJSON.get("idUser"));
		
		JSONArray  linkedInformationJSON = (JSONArray) marcaJSON.get("linkedInformation");
		
		ArrayList<LinkedInfoUnit> linkedInformation = new ArrayList<LinkedInfoUnit>();
		
		for(int i = 0; i < linkedInformationJSON.size(); i++) {
			JSONObject linkUnitJSON = (JSONObject) parser.parse(linkedInformationJSON.get(i).toString());			
			linkedInformation.add(new LinkedInfoUnit(hexStringToByteArray(linkUnitJSON.get("hash").toString()), (boolean) linkUnitJSON.get("right")));
		}
		
		byte[] sig = null;
		
		return new Marca(marcaJSON.get("idUser").toString(),
				(long) marcaJSON.get("serialNumber"),
				(long) marcaJSON.get("timest"),
				hexStringToByteArray(marcaJSON.get("digest").toString()),
				sig,
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
