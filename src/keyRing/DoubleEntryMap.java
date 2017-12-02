package keyRing;

import java.io.Serializable;
import java.util.HashMap;

/**
 * La classe implementa una mappa a due ingressi:
 *    <key1, key2, value>
 *
 * @param <T>  - tipo del primo identificativo
 * @param <U>  - tipo del secondo identificativo
 * @param <A>  - tipo del valore
 */
public class DoubleEntryMap<T, U, A> implements Serializable {

	private static final long serialVersionUID = 3L;
	private HashMap<T, HashMap<U, A>> outMap;
	
	
	public DoubleEntryMap() {
		this.outMap = new HashMap<T, HashMap<U,A>>();	
	}
	
	public HashMap<U, A> getOutValue(T outID) {
		return this.outMap.get(outID);
	}
	
	public HashMap<U, A> putOutValue(T outID, HashMap<U, A> map) {
		return this.outMap.put(outID, map);
	}
	
	public HashMap<U, A> removeOutValue(T outID) {
		return this.outMap.remove(outID);
	}
	
	public HashMap<U, A> replaceOutValue(T outID, HashMap<U, A> map) {
		return this.outMap.replace(outID, map);
	}
	
	public A get(T outID, Object innerID) {
		return this.outMap.get(outID).get(innerID);
	}
	
	public A put(T outID, U innerID, A innerValue) {
		if(this.outMap.get(outID) == null)
			this.outMap.put(outID, new HashMap<U, A>());

		return this.outMap.get(outID).put(innerID, innerValue);
	}
	
	public A remove(T outId, U innerID) {
		return this.outMap.get(outId).remove(innerID);
	}
	
	public A replace(T outID, U innerID, A innerValue) {
		return this.outMap.get(outID).replace(innerID, innerValue);
	}
}
