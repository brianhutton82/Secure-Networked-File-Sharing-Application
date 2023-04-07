/* This list represents the users on the server */
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.lang.StringBuilder;
import java.security.MessageDigest;
import javax.crypto.SecretKey;

/* --- This will need changed to support use of passwords for users --- */

public class UserList implements java.io.Serializable {

    private static final long serialVersionUID = 7600343803563417992L;
    private Hashtable<String, User> list = new Hashtable<String, User>();

    public synchronized void addUser(String username, String password) {
	    User newUser = new User(password);
        list.put(username, newUser);
    }

    public synchronized void deleteUser(String username) {
        list.remove(username);
    }

    public synchronized boolean checkUser(String username) {
        if(list.containsKey(username)) {
            return true;
        } else {
            return false;
        }
    }

   public synchronized boolean checkPassword(String username, String password){
        return list.get(username).checkPassword(password);
   }

    public synchronized ArrayList<String> getUserGroups(String username) {
        return list.get(username).getGroups();
    }

    public synchronized ArrayList<String> getUserOwnership(String username) {
        return list.get(username).getOwnership();
    }

    public synchronized void addGroup(String user, String groupname) {
        list.get(user).addGroup(groupname);
    }

    public synchronized void removeGroup(String user, String groupname) {
        list.get(user).removeGroup(groupname);
    }

    public synchronized void addOwnership(String user, String groupname) {
        list.get(user).addOwnership(groupname);
    }

    public synchronized void removeOwnership(String user, String groupname) {
        list.get(user).removeOwnership(groupname);
    }
    
    public synchronized void setToken(String username, UserToken token){
        list.get(username).setToken(token);
    }

    public synchronized UserToken getToken(String username){
        return list.get(username).getToken();
    }

    public synchronized void removeToken(String username){
        list.get(username).removeToken();
    }

    class User implements java.io.Serializable {
        private static final long serialVersionUID = -6699986336399821598L;
        private ArrayList<String> groups;
        private ArrayList<String> ownership;
	    private byte[] password;
        private UserToken token;

        public User(String pw) {
            groups = new ArrayList<String>();
            ownership = new ArrayList<String>();
            password = hashPassword(pw);
        }

        private byte[] hashPassword(String pw){
            StringBuilder salt = new StringBuilder();
            salt.append("somesaltphrase");
            salt.append(pw);
            try{
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(salt.toString().getBytes());
                return md.digest();
            } catch(Exception e){
                e.printStackTrace();
            }
            return null;
        }

        public boolean checkPassword(String pw){

            byte[] hashedPW = hashPassword(pw);
            return Arrays.equals(hashedPW, this.password);
        }

        public ArrayList<String> getGroups() {
            return groups;
        }

        public ArrayList<String> getOwnership() {
            return ownership;
        }

        public void addGroup(String group) {
            groups.add(group);
        }

        public void removeGroup(String group) {
            if(!groups.isEmpty()) {
                if(groups.contains(group)) {
                    groups.remove(groups.indexOf(group));
                }
            }
        }

        public void addOwnership(String group) {
            ownership.add(group);
        }

        public void removeOwnership(String group) {
            if(!ownership.isEmpty()) {
                if(ownership.contains(group)) {
                    ownership.remove(ownership.indexOf(group));
                }
            }
        }

        public void setToken(UserToken t){
            this.token = t;
        }

        public UserToken getToken(){
            return this.token;
        }

        public void removeToken(){
            this.token = null;
        }

    }

}
