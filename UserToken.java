import java.util.List;
import java.util.ArrayList;
import java.util.Hashtable;
import javax.crypto.SecretKey;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public interface UserToken {
    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer();

    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject();

    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups();

    /**
     * This method will fetch the bytes representing the servers signature 
     */
    public byte[] getServerSignature();

    /**
     * This method allows a server to add a signature to the token
     * @param sig is the byte array representing the signature of the server
     */
    public void addServerSignature(final byte[] sig);
    
    public void removeSignature();

    // remove group from token
    public void removeGroup(String groupname);

    // add groupname to token usergroups
    public void addGroup(String groupname);

    /**
     * This method allows the server to add a timestamp to the token
     * @param ts is the long representing the servers timestamp
     */
    public void setTimestamp(long ts);

    /**
     * This method will fetch a string representation of the timestamp when this token was generated
     */
    public long getTimeStamp();

    /**
     * This method allows the server to add a session ID key H(DHkey || "SID") to the token
     * @param hashedKey is the hashed diffie hellman key unique to a fileserver session timestamp
     */
    public void setSeshIDkey(byte[] hashedKey);

    /**
     * This method will fetch the session id key to check for session continuity
     */
    public byte[] getSeshIDkey();

}   //-- end interface UserToken
