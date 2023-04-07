/* Provides User Facing Application  */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.lang.Object;
import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.util.List;
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;

import java.security.Security;
import java.security.Provider;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;

public class MyClientApp implements java.io.Serializable{

    private static final long serialVersionUID = -7726335089122193103L;

    public static FileClient fc = new FileClient();
    public static GroupClient gc = new GroupClient();

    public static void main(String[] args) {
	// using bouncycastle
	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	// using console to read in users password
	Console cons = System.console();

	//INIT: username and group server, ask for address and port
    Scanner in = new Scanner(System.in);
    in.useDelimiter(System.lineSeparator());
    System.out.print("Enter Username: ");
    String username = in.next();

	// using console to get password so password plaintext is not displayed in command line
	String password = new String(cons.readPassword("%s", "Enter password: "));
	
    System.out.print("Enter Group Server Address: ");
    String gsName = in.next();

    System.out.print("Enter Group Server Port: ");
    int gsPort = in.nextInt();


    // START User Client Interface, establish group client connection
    if(!(gc.connect(gsName, gsPort))){
        System.out.println("Failed to connect to Group Server at address: " + gsName + ", and port: " + gsPort);
    } else {
        
        // Diffie-Hellman key exchange, ensure key exchange was successful
	    if(!gc.establishSecretKey()){
    		System.out.println("Error connecting to server!");
    		System.exit(-1);
	    }

        // Get HMAC key generated by group server
        if(!gc.fetchHMACKey()){
            System.out.println("\n***Unable to fetch HMAC key!***\n");
            System.exit(-1);
        }

        System.out.println("Successfully connected to Group Server at address: " + gsName + ", and port: " + gsPort);

	    // wait for server to initiate Diffie-Hellman key exchange
	    // need to implement client method to put here

        // After group client connection establshed, provide options
        System.out.print("\nRecieving token... ");
        UserToken token = gc.getToken(username, password);
        if(token == null)
        {
            System.out.println("User " + username + " does not exist, exiting...");
            gc.disconnect();
            in.close();
            System.exit(0);
        }

        System.out.print("\nToken recieved.");

        String cmd = "temp";
        Integer view = 0; // view indicates what prompts to display to the user. 0 = group server options, >0 = file server options

        do {

            token = gc.getToken(username, password);
            if(token == null)
            {
                System.out.println("User " + username + " no longer exists, exiting...");
                gc.disconnect();
                in.close();
                System.exit(0);
            }

                
            if(view == 0) // group server display
            {
                System.out.print("\nPlease enter your next command. Options:\n");
                String comOps = "";

                if(token.getGroups().contains("ADMIN"))
                {
                    comOps = "CUSER <user> <password>\nDUSER <user>\n";
                }
                comOps = comOps + "CGROUP <group>\nDGROUP <group>\nADD <user> TO <group>\nREMOVE <user> FROM <group>\nLIST <group> MEMBERS\nESTABLISH FILE SERVER CONNECTION\nDISCONNECT\n";

                System.out.print(comOps);
                cmd = in.next();

                String[] userInput = cmd.split(" ");

                if(userInput[0].equals("CUSER"))
                {
                    String cInputName = userInput[1];
			        String cInputPW = userInput[2];
                    if(gc.createUser(cInputName, cInputPW, token)) { System.out.println("User " + cInputName + " created"); }
                    else
                    {
                        System.out.println("Error creating user " + cInputName);
                    }
                }
                else if(userInput[0].equals("CGROUP"))
                {
                    String cInputGroup = userInput[1];
                    if(cInputGroup.indexOf("_") != -1)
                    {
                        System.out.println("Groups are not allowed to have the '_' character in them.");
                    } else if(gc.createGroup(cInputGroup, token)) {
                        System.out.println("Group " + cInputGroup + " created");
                        token = gc.getToken(username, password);
                    } else {
                        System.out.println("Error creating group " + cInputGroup);
                    }
                } 
                else if(userInput[0].equals("DUSER"))
                {
                    String dInputName = userInput[1];
                    if(gc.deleteUser(dInputName, token)) { System.out.println("User " + dInputName + " deleted"); }
                    else
                    {
                        System.out.println("Error deleting user " + dInputName);
                    }
                }
                else if(userInput[0].equals("DGROUP")) // group
                {
                    String dInputGroup = userInput[1];
                    if(gc.deleteGroup(dInputGroup, token)){ System.out.println("Group " + dInputGroup + " deleted"); }
                }
                else if(userInput[0].equals("ADD")) 
                {
                    String userToAdd = userInput[1];
                    String groupToAddTo = userInput[3];

                    if(gc.addUserToGroup(userToAdd, groupToAddTo, token)) { System.out.println("User " + userToAdd + " added to group " + groupToAddTo);}
                    else
                    {
                        System.out.println("Error adding to group");
                    }
                }
                else if(userInput[0].equals("REMOVE"))
                {
                    String userToRemove = userInput[1];
                    String groupToRemoveFrom = userInput[3];

                    if(gc.deleteUserFromGroup(userToRemove, groupToRemoveFrom, token)) { System.out.println("User " + userToRemove + " deleted from group " + groupToRemoveFrom);}
                    else
                    {
                        System.out.println("Error removing from group");
                    }
                }
                else if(userInput[0].equals("LIST"))
                {
                    String group = userInput[1];
                    List<String> groupList = gc.listMembers(group, token);
                    if(groupList != null){
                        System.out.println("Group " + group + " members: " + groupList.toString());
                    } else {
                        System.out.println("That group does not exist.");
                    }
                }
                else if (userInput[0].equals("ESTABLISH")) // establish file server connection
                {
                    view = -1;
                }
                else if (userInput[0].equals("DISCONNECT"))
                {
                    break;
                }
                else
                {
                    System.out.println("Unknown command: [" + cmd + "], please try again");
                }

            }
            else //file server view
            {
                token = gc.getToken(username, password);
                if(token == null)
                {
                    System.out.println("User " + username + " no longer exists, exiting...");
                    gc.disconnect();
                    fc.disconnect();
                    in.close();
                    System.exit(0);
                }
                
                // on initial connection
                if(view < 0)
                {
                    System.out.print("Enter File Server Address: ");
                    String fsName = in.next();

                    System.out.print("Enter File Server Port: ");
                    int fsPort = in.nextInt();

                    //System.out.print("Enter File Server Number (>0): "); // Can be re-implemented if seperate file servers need to be accessed individually
                    //view = in.nextInt();
                    view = 1;

                    if(!(fc.connect(fsName, fsPort))){
                        System.out.println("Failed to connect to File Server at address: " + fsName + ", and port: " + fsPort);
                        break;
                    } else {
                        System.out.println("Successfully connected to File Server at address: " + fsName + ", and port: " + fsPort);
                    }

                    // Signed Diffie-Hellman key exchange, ensure key exchange was successful
                    if(!fc.establishSecretKey()){
                        System.out.println("Error connecting to server! Key gen failed");
                        System.exit(-1);
                    }

                    // Issue a challenge to the fs
                    if(!fc.issueChallenge())
                    {
                        System.out.println("Error connecting to server! Challenge denied");
                        view = 0;
                    }

                    if(!fc.checkFingerprint(Integer.toString(fsPort)))
                    {
                        System.out.println("Attempted to connect to untrusted server, denying connection.");
                        break;
                    } else {
                        System.out.println("File server fingerprint confirmed, proceding... ");
                    }

                    gc.createSessionIDKey(fc.getSessionDHkey());
                    UserToken tokHolder = gc.storeSessionIDKey(username, token);
                    if(tokHolder == null)
                    {
                        // The hashed value of this sessions DH key acts as a session key. Please see doc/phase4-writeup.htm for more info
                        System.out.println("Failed to update session key.");
                    }
                    else
                    {
                        System.out.println("Session key successfully updated.");
                        token = tokHolder;
                    }
                    
                    
                }

                if(view > 0)
                {
                    System.out.print("\nPlease enter your next command. Options: \nLIST FILES\nUPLOAD <filelocation> <filename> <group>\nDOWNLOAD <filelocation> <filename> <group>\nDELETE <filename>\nDISCONNECT\n");
                    cmd = in.next();

                    String[] userInput = cmd.split(" ");

                    if(userInput[0].equals("DISCONNECT"))
                    {
                        System.out.println("Returning to group server...");
                        fc.disconnect();
                        view = 0;
                    } 
                    else if(userInput[0].equals("LIST"))
                    {
                        try{
                            List<String> fileList = fc.listFiles(token);
                            System.out.println("Accessible files: " +  fileList.toString());
                        } catch (Exception ex){
                            System.out.println("Error listing files");
                        }
                    }
                    else if(userInput[0].equals("UPLOAD")) 
                    {
                        String fileLoc  = userInput[1];
                        String fileName = userInput[2];
                        String group    = userInput[3];
                        token = gc.getToken(username, password); //requesting a new token here messes up the T7 protocols.

                        // fetch most recent key
                        SecretKey sk = gc.getGroupKey(username, group, -1);

                        // get key index
                        int keyIndex = gc.getKeyIndex(username, group, sk);

                        // store key index on file servers fileList, that way other group members can retrieve the key from the group server to decrypt these files
                        boolean keyStored = fc.storeKeyIndex(fileName, keyIndex);

                        // encrypt file contents and upload to file server
                        byte[] fileContents = null;
                        byte[] encryptedContents = null;

                        try {
                            fileContents = Files.readAllBytes(Paths.get(fileLoc));
                            Cipher cipher = Cipher.getInstance("AES", "BC");
                            cipher.init(Cipher.ENCRYPT_MODE, sk);
                            encryptedContents = cipher.doFinal(fileContents);
                        } catch (Exception e) {
                            System.out.println("\n***Ran into error when encrypting file!***\n");
                        }


                        //File is stored in shared_files as _<group>_<filename>
                        if(fileName.indexOf("_") != -1) {
                            System.out.println("File names are not allowed to have the '_' character in them.");
                        } else if((encryptedContents != null) && fc.upload(fileLoc, group + "/" + fileName, group, token, encryptedContents) && keyStored) {
                            System.out.println("Successfully uploaded file " + fileName + " from location " + fileLoc + " to group " + group);
                        }
                    }
                    else if(userInput[0].equals("DOWNLOAD"))
                    {
                        String fileLoc  = userInput[1]; // this is how the file is stored, ie /group/test.txt
                        String fileName = userInput[2]; // this is how the file will be downloaded, whatever you want on your system
                        String group = userInput[3];

                        String tempFilename = fileLoc.substring(fileLoc.lastIndexOf("/") + 1);
                        int keyIndex = fc.getKeyIndex(tempFilename);
                        SecretKey sk = gc.getGroupKey(username, group, keyIndex);

                        // get bytes from file server, decrypt with sk, then write to file
                        File file = new File(fileName);
                        if (!file.exists()) {
                            try {
                                file.createNewFile();
                                FileOutputStream fos = new FileOutputStream(file);
                                byte[] fileContents = fc.download(fileLoc, fileName, token);
                                byte[] decryptedContents = null;

                                if (fileContents != null) {
                                    try {
                                        Cipher cipher = Cipher.getInstance("AES", "BC");
                                        cipher.init(Cipher.DECRYPT_MODE, sk);
                                        decryptedContents = cipher.doFinal(fileContents);
                                    } catch (Exception e) {
                                        System.out.println("\n***Ran into error when decrypting file contents!***\n");
                                        e.printStackTrace();
                                    }
                                    fos.write(decryptedContents);
                                    fos.close();
                                    System.out.println("Successfully downloaded file " + fileLoc + " as " + fileName);
                                }  
                            } catch (Exception e){
                                System.out.println("\n***Error decrypting downloaded file!***\n");
                                e.printStackTrace();
                            }

                        }
                    }
                    else if(userInput[0].equals("DELETE"))
                    {
                        String fileName  = userInput[1];
                        if(fc.delete(fileName, token)) { System.out.println("Successfully deleted file " + fileName); }
                    }
                    else
                    {
                        System.out.println("Unknown command: [" + cmd + "], please try again");
                    }
                }

            }
                
        } while(cmd.compareTo("DISCONNECT") != 0 || view == 0); 
           
    }

        System.out.println("\nExiting...");
        gc.disconnect();
        in.close();
    
    }
    
}
