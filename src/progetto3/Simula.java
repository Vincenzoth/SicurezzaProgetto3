package progetto3;

import java.util.ArrayList;

public class Simula {
	public static void main(String[] args) {
		TSA myTSA = new TSA();
		ArrayList<Richiesta> requests = new ArrayList<Richiesta>();
		// costruisci l'rray di richieste
		int numRequest = 8;

		for (int i = 0; i<numRequest; i++) {
			//trova i h random
		}

		ArrayList<Marca> marche = myTSA.metodo(requests);
		
		// verifica
	}
	
	public static void verfy(Marca m, byte[] hash, byte[] rootHash)	{
		// ricalcola il rootHash con hash che calcoli tu
		// e controlla che questo sia uguale a rootHash pubblicato
	}
}
