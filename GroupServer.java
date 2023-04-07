/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */


/* Adding public key and private key to group server so that a secret symmetric key can be exchanged at some point */


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.net.ServerSocket;
import java.net.Socket;

import java.util.Scanner;
import java.util.Arrays;

import java.security.Security;
import java.security.Provider;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class GroupServer extends Server {

    public UserList userList;
    public GroupList groupList;
    public PublicKey publicKey;
    protected PrivateKey privateKey;

    public GroupServer(int _port) {
        super(_port, "alpha");
	    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();
            this.publicKey = keyPair.getPublic();
            this.privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void start() {
        // Overwrote server.start() because if no user file exists, initial admin account needs to be created

        String userFile = "UserList.bin";
    	String groupFile = "GroupList.bin";
        Scanner console = new Scanner(System.in);
        ObjectInputStream userStream;
        ObjectInputStream groupStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        runtime.addShutdownHook(new ShutDownListener(this));

    	System.out.print("\nEnter your username: ");
    	String username = console.next();
    	System.out.print("Enter your password: ");
    	String password = console.next();


        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(userFile);
            userStream = new ObjectInputStream(fis);
            userList = (UserList)userStream.readObject();

    	    if((!userList.checkUser(username)) || !(userList.checkPassword(username, password)) || (userList.getUserGroups(username) == null) || (!userList.getUserGroups(username).contains("ADMIN"))) {
        		System.out.println("\n***Username does not exist, or user is not an admin, or password is incorrect***");
        		System.exit(-1);
    	    }

        } catch(FileNotFoundException e) {
            System.out.println("\n***UserList File Does Not Exist. Creating UserList...***");
            System.out.println("***No users currently exist. Your account will be the administrator.***");
            //Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
            userList = new UserList();

    	    try{
    	    	userList.addUser(username, password);
            	userList.addGroup(username, "ADMIN");
            	userList.addOwnership(username, "ADMIN");
    	    } catch(Exception ex){
    		    ex.printStackTrace();
    	    }
        } catch(IOException e) {
            System.out.println("\n***Error reading from UserList file***");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("\n***Error reading from UserList file***");
            System.exit(-1);
        }

	// Open group file to get group list
	try {
		FileInputStream fgs = new FileInputStream(groupFile);
		groupStream = new ObjectInputStream(fgs);
		groupList = (GroupList)groupStream.readObject();
	}
	catch(FileNotFoundException e){
		System.out.println("***GroupList File Does not Exist. Creating GroupList...***");
		System.out.println("***No groups currently exist. Your account will be added to the group: ADMIN.***");

		// If no GroupList file exists, create a new one and add the current user to the ADMIN group
		groupList = new GroupList();
		groupList.createGroup("ADMIN", username);
	} catch(IOException e){
		System.out.println("Error reading from GroupList file");
		System.exit(-1);
	} catch(ClassNotFoundException e){
		System.out.println("Error reading from GroupList file");
		System.exit(-1);
	}

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSave aSave = new AutoSave(this);
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("\n%s up and running\n", this.getClass().getName());

            Socket sock = null;
            GroupThread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new GroupThread(sock, this);
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

    }

}

//This thread saves the user list
class ShutDownListener extends Thread {
    public GroupServer my_gs;

    public ShutDownListener (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;
        ObjectOutputStream outStreamGroups;

	    try {
            outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
            outStream.writeObject(my_gs.userList);
            outStreamGroups = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
	        outStreamGroups.writeObject(my_gs.groupList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

    }
}

class AutoSave extends Thread {
    public GroupServer my_gs;

    public AutoSave (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave group and user lists...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
                    outStream.writeObject(my_gs.userList);
		            outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
		            outStream.writeObject(my_gs.groupList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }

            } catch(Exception e) {
                System.out.println("Autosave Interrupted");
            }
        } while(true);
    }
}
