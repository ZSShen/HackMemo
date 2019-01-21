import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Driver {

	public static void main(String [] args) {

		Map<String, String> map = new HashMap<String, String>();
		map.put("123", "abc");
		map.put("456", "def");
		iterateMap(map);

		Set<String> set = new HashSet<String>();
		set.add("789");
		set.add("ghi");
		iterateSet(set);
	}

	public static <K, V> void iterateMap(Map<K, V> map) {

		for (Map.Entry<K, V> entry : map.entrySet()) {
			K key = entry.getKey();
			V value = entry.getValue();
			System.out.println(key + " -> " + value);
		}
	}

	public static <K> void iterateSet(Set<K> set) {

		for (K key : set) {
			System.out.println(key);
		}
	}
}
