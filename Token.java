import java.util.List;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Hashtable;
import javax.crypto.SecretKey;

public class Token implements UserToken, java.io.Serializable{

	private static final long serialVersionUID = -7726342089122193103L;

	private String issuer; // issuer of token, the group server that created this token
	private String subject; // name of subject of token
	private ArrayList<String> usergroups; // list of group memberships that the owner of this token has access to
	private byte[] signature; // signature of server who created this token
	private long timestamp; //  timestamp when this token was generated using long milliseconds since epoch
	private byte[] sessionIDkey; // = H(DHsessionKey || "SID"), used as a session key
	private boolean inUse = false; // indicates if the session key is used for the current session. Prevents users from using tokens that are in use by other users

	public Token(String name, String username, ArrayList<String> groups){
		this.issuer = name;
		this.subject = username;
		this.usergroups = new ArrayList<String>();
		this.signature = null;
		this.timestamp = 0;
		this.sessionIDkey = null;
		// add all groups from arraylist to this tokens list of usergroups
		for(String group : groups){
			usergroups.add(group);
		}

	}

	// returns issuer of token
	public String getIssuer() {
		return this.issuer;
	}

	// returns string indicating name of subject of token
	public String getSubject(){
		return this.subject;
	}

	// extracts list of groups that owner of token has access to
	public List<String> getGroups(){
		return this.usergroups;
	}

	public void removeGroup(String groupname){
		this.usergroups.remove(groupname);
	}

	public void addGroup(String groupname){
		if(!this.usergroups.contains(groupname)){
			this.usergroups.add(groupname);
		}
	}

	// get bytes representing servers signature
	public byte[] getServerSignature(){
		return this.signature;
	}

	// used by server to sign token
	public void addServerSignature(byte[] sig){
		this.signature = sig;
	}

	public void removeSignature(){
		this.signature = null;
	}

	public void setTimestamp(long ts){
		this.timestamp = ts;
	}

	public long getTimeStamp(){
		return this.timestamp;
	}

	public void setSeshIDkey(byte[] seshIDkey){
		this.sessionIDkey = seshIDkey;
	}

	public byte[] getSeshIDkey(){
		return this.sessionIDkey;
	}

	@Override
	public String toString(){
		StringBuilder tostring = new StringBuilder();
		tostring.append(issuer + " ");
		tostring.append(subject);

		for(String group : usergroups){
			tostring.append(" " + group);
		}

		tostring.append(" " + timestamp);

		return tostring.toString();
	}
}
