/* Tracks Groups on Group Server */
// Referenced UserList.java for serializable
import java.util.ArrayList;
import java.util.Hashtable;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;

public class GroupList implements java.io.Serializable {

	
	private static final long serialVersionUID = 5330967207974162412L;


	private Hashtable<String, ArrayList<String>> hashTable = new Hashtable<String, ArrayList<String>>();
	//private Hashtable<String, SecretKey> groupKeys = new Hashtable<String, SecretKey>();
	private Hashtable<String, ArrayList<SecretKey>> groupKeys = new Hashtable<String, ArrayList<SecretKey>>();

	// the first entry of the ArrayList for a group will be the group owner
	public synchronized void createGroup(String groupname, String groupOwner){
		ArrayList<String> newGroup = new ArrayList<String>();
		newGroup.add(groupOwner);
		hashTable.put(groupname, newGroup);
	}

	public synchronized void removeGroup(String groupname){
		hashTable.remove(groupname);
	}

	public synchronized ArrayList<String> getGroupMembers(String groupname){
		return hashTable.get(groupname);
	}

	public synchronized void addMember(String username, String groupname){
		hashTable.get(groupname).add(username);
	}

	public synchronized void removeMember(String username, String groupname){
		if (!checkOwner(username, groupname)){
			hashTable.get(groupname).remove(username);
		}
	}

	public synchronized boolean checkOwner(String username, String groupname){
		return hashTable.get(groupname).get(0).equals(username);
	}

	public synchronized void removeOwner(String groupname){
		hashTable.get(groupname).set(0, null);

	}

	public synchronized boolean checkIfgroupExists(String groupname){
		return hashTable.containsKey(groupname);
	}

	public synchronized boolean isUserMemberOfGroup(String username, String groupname){
		if(hashTable.get(groupname) == null) // if group does not exist, cancel
		{
			return false;
		}
		return hashTable.get(groupname).contains(username);
	}

	// get encryption/decryption key for file upload/download on file server
	public synchronized SecretKey getKey(String groupname){
		// most recently used key will be at end of arraylist, keys can be specified by position in arraylist
		int indexOfCurrentKey = groupKeys.get(groupname).size() - 1;
		return groupKeys.get(groupname).get(indexOfCurrentKey);
	}

	// fetch specific key for group by index
	public synchronized SecretKey getKey(String groupname, int pos){
		return groupKeys.get(groupname).get(pos);
	}

	public synchronized int getKeyPos(String groupname, SecretKey key){
		return groupKeys.get(groupname).indexOf(key);
	}

	// generate key and add it to groupKeys hash table
	public synchronized void generateKey(String groupname){
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
			keyGen.init(256);
			SecretKey secretKey = keyGen.generateKey();
			ArrayList<SecretKey> gks = groupKeys.get(groupname);
			if(gks == null){
				gks = new ArrayList<SecretKey>();
			}
			gks.add(secretKey);
			groupKeys.put(groupname, gks);
		} catch(Exception e){
			System.out.println("\n***Failed to generate key for group: " + groupname + " for file encryption & decryption!***\n");
			e.printStackTrace();
		}
	}

	public synchronized void removeGroupKey(String groupname){
		groupKeys.remove(groupname);
	}
}
