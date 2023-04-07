/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import java.security.Security;
import java.security.SecureRandom;
import java.security.Provider;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.Mac;


public class GroupThread extends Thread {
    private final Socket socket;
    private GroupServer my_gs;
    Signature s;
    public PublicKey groupServerPublicKey;
    private PrivateKey groupServerPrivateKey;
    public PublicKey clientPublicRSAKey;
    private SecretKey clientServerKey;
    private SecretKey hmacKey;
    // Large primes sourced from: Beginning Cryptography with Java by David Hook
	private BigInteger generator = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7" + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b" + "410b7a0f12ca1cb9a428cc", 16);
	private BigInteger primeModulus = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387" + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b" + "f0573bf047a3aca98cdf3b", 16);
	private int agreedUponCounter = 42; // agreed upon out-of-band by both parties

    public GroupThread(Socket _socket, GroupServer _gs) {
        socket = _socket;
        my_gs = _gs;
    }

	public void run() {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		int expectedCounter = agreedUponCounter;
		boolean proceed = true;

		try {
			s = Signature.getInstance("SHA384withRSA", "BC"); // initialize signature

			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			// if Diffie-Hellman Key Exchange failed
			if(!establishSecretKey(input, output)){
				System.out.println("Client failed to authenticate");
				System.exit(-1);
			}

			// send client secret key for HMAC
			if(!sendHMACkey(input, output)){
				System.out.println("\n***Unable to send HMAC key, exiting!***\n");
				System.exit(-1);
			}

			do {
				Envelope message = (Envelope)input.readObject();

				// ensure message was not altered
				if ((message.getHMAC() != null) && !checkHMAC(message)) {
					System.out.println("\n***Detected alteration in message, exiting!***\n");
					System.exit(-1);
				}

				// ensure message was not reordered
				if (!message.checkCounter(agreedUponCounter) && !message.checkCounter(expectedCounter)) {
					System.out.println("\n***Counter in message contains unexpected value, potential replay attack, exiting!***\n");
					System.exit(-1);
				}

				// decrypt envelope if encrypted
				if (message.getMessage().equals("ENCRYPTED")) {
					byte[] contents = (byte[])message.getObjContents().get(0);
					message = decryptEnvelope(contents);
				}

				System.out.println("Request received: " + message.getMessage());
				Envelope response = new Envelope("FAIL");

				String command = message.getMessage();

				String username, password, groupname, requester;
				username = password = groupname = requester = null;
				UserToken yourToken = null;

				switch (command) {

					case "GET":
						username = (String)message.getObjContents().get(0); //Get the username
						password = (String)message.getObjContents().get(1); //Get the password

						// if password checks out, fetch token or create a new one
						if (my_gs.userList.checkPassword(username, password)) {

							yourToken = my_gs.userList.getToken(username);
							if (yourToken == null) {
								System.out.println("\n***No Token for " + username + " found in user list, creating new token!***\n");
								yourToken = createToken(username, password); //Create a token
							}

							if (yourToken != null) {
								response = new Envelope("OK");
								yourToken = addSignatureToToken(yourToken);
								response.addObject(yourToken);
							}
						}
						break;

					case "CUSER":
						username = (String)message.getObjContents().get(0); //Extract the username
						yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
						password = (String)message.getObjContents().get(2); //Extract the password
						if (createUser(username, yourToken, password)) {
							response = new Envelope("OK"); // Success
							saveState();
						}
						break;

					case "DUSER":
						loadState();
						username = (String)message.getObjContents().get(0); //Extract the username
						yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
						if (deleteUser(username, yourToken)) {
							response = new Envelope("OK"); // Success
							saveState();
						}
						break;

					case "CGROUP":
						loadState();
						groupname = (String)message.getObjContents().get(0);
						yourToken = (UserToken)message.getObjContents().get(1);
						if (createGroup(groupname, yourToken)) {
							response = new Envelope("OK");
							saveState();
						}
						break;

					case "DGROUP":
						loadState();
						groupname = (String)message.getObjContents().get(0);
						yourToken = (UserToken)message.getObjContents().get(1);

						if (deleteGroup(groupname, yourToken)) {
							response = new Envelope("OK");
							saveState();
						}
						break;

					case "LMEMBERS":
						groupname = (String)message.getObjContents().get(0);
						yourToken = (UserToken)message.getObjContents().get(1);
						username = (String)yourToken.getSubject();
						// If this user is a member of the group
						if (my_gs.userList.checkUser(username)) {
							loadState();
							ArrayList<String> groupMembersList = my_gs.groupList.getGroupMembers(groupname);
							response = new Envelope("OK");
							response.addObject(groupMembersList);
						}
						break;

					case "AUSERTOGROUP":
						loadState();
						username = (String)message.getObjContents().get(0);
						groupname = (String)message.getObjContents().get(1);
						yourToken = (UserToken)message.getObjContents().get(2);
						requester = (String)yourToken.getSubject();
						if (addUserToGroup(username, requester, groupname, yourToken)) {
							response = new Envelope("OK");
						}
						break;

					case "RUSERFROMGROUP":
						username = (String)message.getObjContents().get(0);
						groupname = (String)message.getObjContents().get(1);
						yourToken = (UserToken)message.getObjContents().get(2);
						requester = yourToken.getSubject();
						if (removeUserFromGroup(username, requester, groupname, yourToken)) {
							response = new Envelope("OK");
						}
						break;

					case "GETGROUPKEY":
						username = (String)message.getObjContents().get(0);
						groupname = (String)message.getObjContents().get(1);
						int pos = (int)message.getObjContents().get(2);
						SecretKey groupkey = getGroupKey(username, groupname, pos);
						if (groupkey != null) {
							response = new Envelope("OK");
							response.addObject(groupkey);
						}
						break;
						
					case "GETKEYPOS":
						username = (String)message.getObjContents().get(0);
						groupname = (String)message.getObjContents().get(1);
						SecretKey secretkey = (SecretKey)message.getObjContents().get(2);
						int index = getKeyIndex(username, groupname, secretkey);
						if(index >= 0) {
							response = new Envelope("OK");
							response.addObject(index);
						}
						break;
					
					case "GETSESSIONIDKEY":
						username = (String)message.getObjContents().get(0);
						byte[] sessionIDkey = (byte[])message.getObjContents().get(1);
						UserToken midTok = (UserToken)message.getObjContents().get(2);
						UserToken newTok = setHashedDH(username, sessionIDkey, midTok);
						if(newTok != null) {
							response = new Envelope("OK");
							response.addObject(newTok);
						}
						break;

					case "DISCONNECT":
						saveState();
						socket.close(); //Close the socket
						proceed = false; //End this communication loop
					default:
						break;
				}

				if (proceed) {
					// encrypt envelope and add HMAC before sending
					byte[] encryptedEnvelopeBytes = encryptEnvelope(response);
					response = new Envelope("ENCRYPTED");
					response.addObject(encryptedEnvelopeBytes);
					expectedCounter++; // also increment local counter
					response.setCounter(expectedCounter); // update counter in Envelope
					byte[] responseHMAC = calculateHMAC(response); // after encrypting message, HMAC is added to message to detect message modification
					response.setHMAC(responseHMAC);
					output.writeObject(response);
				}
				
			} while (proceed);

		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}


    public boolean verifyTokenNotModified(UserToken t){
    	boolean result = false;
    	try {
    		byte[] sig = t.getServerSignature(); // extract signature from token
    		s.initSign(this.groupServerPrivateKey);
    		s.update(t.toString().getBytes()); // add string representation
    		byte[] newSig = s.sign(); // get bytes representing signature
    		result = Arrays.equals(sig, newSig); // ensure signatures are equal
    	} catch(Exception e){
    		System.out.println("\n***Unable to verify token!***\n");
    		e.printStackTrace();
    	}
    	return result;
    }

    public UserToken addSignatureToToken(UserToken t){
    	try {
    		s.initSign(this.groupServerPrivateKey); // init signature with RSA private key
    		s.update(t.toString().getBytes("UTF-8")); // add stringified token
    		byte[] sig = s.sign();
    		t.addServerSignature(sig);
    	} catch(Exception e){
    		System.out.println("\n***Unable to add signature to token!***\n");
    		e.printStackTrace();
    	}
		return t;
    }

    //Method to create tokens
    private UserToken createToken(String username, String password) {
        //Check that user exists
		if(my_gs.userList.checkUser(username) && (my_gs.userList.checkPassword(username, password))) {
            //Issue a new token with server's name, user's name, and user's groups
		    saveState();
		    loadState();
		    ArrayList<String> ownedGroups = my_gs.userList.getUserOwnership(username);
		    ArrayList<String> joinedGroups = my_gs.userList.getUserGroups(username);
		    for(String group : joinedGroups){
		    	if (!ownedGroups.contains(group)) {
		    		ownedGroups.add(group);
		    	}
		    }
            UserToken yourToken = new Token(my_gs.name, username, ownedGroups);
			Long ts = System.currentTimeMillis();
			yourToken.setTimestamp(ts);

            my_gs.userList.setToken(username, yourToken); // add users token to userList
		    saveState();
            return yourToken;
        }
        return null;
    }

    //Method to create a user
    private boolean createUser(String username, UserToken yourToken, String password) {
        String requester = yourToken.getSubject();
        //Check if requester exists
        if(my_gs.userList.checkUser(requester)) {
            //Get the user's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administrator
            if(temp.contains("ADMIN")) {
                //Does user already exist?
                if(my_gs.userList.checkUser(username)) {
                    return false; //User already exists
                } else {
                    my_gs.userList.addUser(username, password);
                    //my_gs.userList.setToken(username, yourToken);

		    		saveState();
                    return true;
                }
            } else {
                return false; //requester not an administrator
            }
        } else {
            return false; //requester does not exist
        }
    }

    //Method to delete a user
    private boolean deleteUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Does requester exist?
        if(my_gs.userList.checkUser(requester)) {
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administer
            if(temp.contains("ADMIN")) {
                //Does user exist?
                if(my_gs.userList.checkUser(username)) {

                    //User needs deleted from the groups they belong
                    ArrayList<String> deleteFromGroups = new ArrayList<String>();

                    //This will produce a hard copy of the list of groups this user belongs
                    for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
                        deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
                    }

                    //Delete the user from the groups
                    //If user is the owner, removeMember will automatically delete group!
                    for(int index = 0; index < deleteFromGroups.size(); index++) {
                        my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
                    }

                    //If groups are owned, they must be deleted
                    ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

                    //Make a hard copy of the user's ownership list
                    for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
                        deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
                    }

                    //Delete owned groups
                    for(int index = 0; index < deleteOwnedGroup.size(); index++) {
                        //Use the delete group method. Token must be created for this action
                        deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
                    }
	                // Delete the user from the user list
	                my_gs.userList.deleteUser(username);

				    // Save state of my_gs.groupList & my_gs.userList after removing user
				    saveState();

                    return true;
                } else {
                    return false; //User does not exist

                }
            } else {
                return false; //requester is not an administrator
            }
        } else {
            return false; //requester does not exist
        }
    }

    // Method to create group
    private boolean createGroup(String groupname, UserToken token){
		boolean result = false;
		String requester = token.getSubject();
		// first check to see if this user exists
		if(my_gs.userList.checkUser(requester)){
			// make sure group does not exist already
			if(!my_gs.groupList.checkIfgroupExists(groupname)){
				// create new group with requester as owner
				my_gs.groupList.createGroup(groupname, requester);
				my_gs.groupList.generateKey(groupname);
				saveState();
				my_gs.userList.addOwnership(requester, groupname);
				my_gs.userList.addGroup(requester, groupname);
				token.addGroup(groupname);
				my_gs.userList.setToken(requester, token);
				saveState();
				result = true;
			}
		}
		return result;
    }

    // Method to delete a group
    private boolean deleteGroup(String groupname, UserToken token){
		boolean result = false;
		String requester = token.getSubject();
		// first check and make sure the user exists
		if(my_gs.userList.checkUser(requester)){
			// as long as the requester is not trying to delete the ADMIN group
			// and as long as the user is not trying to delete a group that doesnt exist
			if(!groupname.equals("ADMIN") && my_gs.groupList.checkIfgroupExists(groupname)){
				// check to see if the user has privelege to delete group (the requester == the group creator/owner)
				// if owner of group or admin then you can delete group
				if(my_gs.groupList.checkOwner(requester, groupname) || token.getGroups().contains("ADMIN")){

					// remove groups key entry in group list
					my_gs.groupList.removeGroupKey(groupname);

					// indicate that this user is no longer the owner of this group in the userlist
					my_gs.userList.removeOwnership(requester, groupname);

					token.removeGroup(groupname);
					my_gs.userList.setToken(requester, token);

					// get list of all members of the group
					ArrayList<String> groupMembers = my_gs.groupList.getGroupMembers(groupname);

	                if(groupMembers == null)
	                {
	                    return false;
	                }

					// remove all users from group in userList
					for(String member : groupMembers){
						my_gs.userList.removeGroup(member, groupname);
					}

					// remove the group and return true
					my_gs.groupList.removeGroup(groupname);
					result = true;
					saveState();
				}
			}
		}
		return result;
    }

    private void saveState(){
	    try {
			ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			oos.writeObject(my_gs.groupList);
			oos = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			oos.writeObject(my_gs.userList);
			oos.close();
	    } catch (Exception e) {
			System.out.println("unable to save state of groupList or userList");
	    }
    }

    private void loadState(){
		try {
			FileInputStream groupInStream = new FileInputStream("GroupList.bin");
			ObjectInputStream groupStream = new ObjectInputStream(groupInStream);
			my_gs.groupList = (GroupList)groupStream.readObject();
			groupInStream.close();
			groupStream.close();

			FileInputStream userInStream = new FileInputStream("UserList.bin");
			ObjectInputStream userStream = new ObjectInputStream(userInStream);
			my_gs.userList = (UserList)userStream.readObject();
			userInStream.close();
			userStream.close();
		} catch (Exception e) {
			System.out.println("unable to load state of groupList");
		}
    }

    /* generates public & private key pair for asymmetric encryption
     * returns true if we successfully generate key pair */
    private boolean serverGenerateKeyPair(){
		boolean result = false;
		try {
			
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			groupServerPublicKey = kp.getPublic();
			groupServerPrivateKey = kp.getPrivate();

			// write group servers public key to file so file server can retrieve it later
			FileOutputStream keyfos = new FileOutputStream("groupserverpubkey.key");
			keyfos.write(groupServerPublicKey.getEncoded());
			keyfos.close();
			
			result = true;
		} catch(Exception e){
			e.printStackTrace();
		}
		return result;
    }


    private boolean exchangeAsymmetricPublicKeys(ObjectInputStream input, ObjectOutputStream output){
    	boolean result = false;

    	// initialize RSA keys
		if(!serverGenerateKeyPair()){
			// unable to generate rsa keys
			System.exit(-1);
		}
		try {
			System.out.println("\n***Sending client Group Servers asymmetric public key...***");
			Envelope message = new Envelope("PUBKEY");
			message.addObject(this.groupServerPublicKey.getEncoded());
			output.writeObject(message);

			// client sending back RSA pub key
			Envelope response = (Envelope)input.readObject();

			if(response.getMessage().equals("PUBKEY") && (response.getObjContents().get(0) != null)){
				this.clientPublicRSAKey = (PublicKey)response.getObjContents().get(0);
				Envelope finalResponse = new Envelope("OK");
				output.writeObject(finalResponse);
				System.out.println("***Asymmetric public key sent succesfully***");
				result = true;
			}
		} catch(Exception e){
			e.printStackTrace();
		}
		return result;
    }

    

    // Diffie-Hellman Key Exchange to establish shared secret key between server & client
    private boolean establishSecretKey(ObjectInputStream input, ObjectOutputStream output){
		boolean result = false;
		// Exchange public RSA keys with client
		if(!exchangeAsymmetricPublicKeys(input, output)){
			System.out.println("\n***Error exchanging asymmetric public keys. Exiting");
			System.exit(-1);
		}

		try {
			// set up for DH keys
	        DHParameterSpec dhParameters = new DHParameterSpec(primeModulus, generator);
	        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "BC");
	        kpg.initialize(dhParameters);
	        KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH", "BC");
			KeyPair serverPair = kpg.generateKeyPair();
	        serverKeyAgree.init(serverPair.getPrivate());

			System.out.println("\n***Initiating Diffie-Hellman Key Exchange!***");

			// send client envelope requesting DH key exchange
			Envelope message = new Envelope("DH");

			// Encrypt server-DH-pub-key with clients RSA public key and send to client -- remove this?
			Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, this.clientPublicRSAKey);
			PublicKey serverPubKey = (PublicKey)serverPair.getPublic();

			byte[] wrappedDHPubKey = cipher.doFinal(serverPubKey.getEncoded()); // just add key instead of encrypting
			message.addObject(wrappedDHPubKey);
			output.writeObject(message);
			
			System.out.println("***Awaiting response from client...***");
			// retrieve clients response and get clients public key
			Envelope response = (Envelope)input.readObject();
			System.out.println("***Client response received, sending Client challenge...***");

			if(response.getMessage().equals("DH") && (response.getObjContents().get(0) != null) /*&& response.checkCounter(counter)*/){

				// Decrypt clients DH public key using the servers private RSA key
				Cipher ciph = Cipher.getInstance("RSA", "BC");
				ciph.init(Cipher.DECRYPT_MODE, this.groupServerPrivateKey);
				byte[] temp = (byte[])response.getObjContents().get(0);
				byte[] clientDecryptedDHpubKey = ciph.doFinal(temp);
				PublicKey clientKey = (PublicKey)KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(clientDecryptedDHpubKey));

				serverKeyAgree.doPhase(clientKey, true);
				clientServerKey = serverKeyAgree.generateSecret("AES[256]");

				Envelope success = new Envelope("OK");
				output.writeObject(success);
				result = true;

				System.out.println("***Mutal Key Established! New connection established!***\n");
			}
		} catch(Exception e){
        	e.printStackTrace();
        }

    	return result;
    }

    public byte[] encryptEnvelope(Envelope message){
        byte[] encryptedEnvelope = null;
        try{
            Cipher cipher = Cipher.getInstance("AES", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, this.clientServerKey);
            byte[] serializedEnvelope = serializeEnvelope(message);
            encryptedEnvelope = cipher.doFinal(serializedEnvelope);
        } catch(Exception e){
            e.printStackTrace();
        }
        return encryptedEnvelope;
    }

    /* Convert envelope into byte array */
    private byte[] serializeEnvelope(Envelope message){
        byte[] result = null;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(message);
            result = baos.toByteArray();
        } catch(Exception e){
            System.out.println("\n***Unable to serialize envelope!***");
            e.printStackTrace();
        }
        return result;
    }

    public Envelope decryptEnvelope(byte[] encryptedContents){
        Envelope result = null;
        try {
            Cipher cipher = Cipher.getInstance("AES", "BC");
            cipher.init(Cipher.DECRYPT_MODE, this.clientServerKey);
            byte[] decryptedContents = cipher.doFinal(encryptedContents);
            result = (Envelope)deserializeEnvelope(decryptedContents);
        } catch(Exception e){
            System.out.println("\n***Unable to decrypt envelope!***");
            e.printStackTrace();
        }
        return result;
    }

    /* convert byte array representing envelope into envelope */
    private Object deserializeEnvelope(byte[] env){
        Object result = null;
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(env);
            ObjectInputStream ois = new ObjectInputStream(bis);
            result = ois.readObject();
        } catch(Exception e){
            System.out.println("\n***Unable to deserialize envelope!***");
            e.printStackTrace();
        }
        return result;
    }


	// send client HMAC key to check for tampered messages
	private boolean sendHMACkey(ObjectInputStream input, ObjectOutputStream output){
		boolean result = false;
		//int counter = 1;
		try {
			// initialize key
			KeyGenerator keygen = KeyGenerator.getInstance("HmacSHA512", "BC");
			keygen.init(256);
			this.hmacKey = keygen.generateKey();

			System.out.println("***Sending client HMAC secret key...***\n");
			Envelope message = new Envelope("HMACKEY");
			message.addObject(this.hmacKey);

			// encrypt envelope and send to client
			byte[] encryptedEnvelopeBytes = encryptEnvelope(message);
			Envelope encryptedEnvelope = new Envelope("ENCRYPTED");
			encryptedEnvelope.addObject(encryptedEnvelopeBytes);
			output.writeObject(encryptedEnvelope);

			Envelope response = (Envelope)input.readObject();
			if(response.getMessage().equals("ENCRYPTED")){
	        	byte[] encryptedContents = (byte[])response.getObjContents().get(0);
	        	response = decryptEnvelope(encryptedContents);
	        }
			
			// check to make sure client responded with "OK"
			if(response.getMessage().equals("OK")){
				result = true;
			}
		} catch(Exception e){
			System.out.println("\n***Unable to generate HMAC key!***\n");
			e.printStackTrace();
		}
		return result;
	}

	public byte[] calculateHMAC(Envelope message){
		byte[] result = null;
		byte[] data = serializeEnvelope(message);
		try{
			Mac hmac = Mac.getInstance("HmacSHA512", "BC");
			hmac.init(hmacKey);
			result = hmac.doFinal(data);
		} catch(Exception e){
			System.out.println("\n***Error calculating HMAC!***\n");
			e.printStackTrace();
		}
		return result;
	}

	public boolean checkHMAC(Envelope message){
		boolean result = false;
		byte[] hmacInMessage = message.getHMAC(); // check HMAC in message
		message.removeHMAC();
		byte[] calculatedHMAC = calculateHMAC(message);
		if(Arrays.equals(hmacInMessage, calculatedHMAC)){
			result = true;
		}
		return result;
	}

	public boolean addUserToGroup(String username, String requester, String groupname, UserToken token){
		boolean result = false;
		try {
			boolean userExists = my_gs.userList.checkUser(username);
			boolean requesterExists = my_gs.userList.checkUser(requester);
			boolean groupExists = my_gs.groupList.checkIfgroupExists(groupname);
			boolean requesterIsOwner = my_gs.groupList.checkOwner(requester, groupname);

			if(userExists && requesterExists && groupExists && requesterIsOwner){
				my_gs.groupList.addMember(username, groupname);
				my_gs.userList.addGroup(username, groupname);
				token.addGroup(groupname);
				my_gs.userList.setToken(username, token);
				result = true;
				saveState();
			}
		} catch(Exception e){
			System.out.println("\n\t*** Failed to add user to group! ***\n");
		}
		return result;
	}


	public boolean removeUserFromGroup(String username, String requester, String groupname, UserToken token){
		boolean result = false;
		try {

			boolean userExists = my_gs.userList.checkUser(username);
			boolean requesterExists = my_gs.userList.checkUser(requester);
			boolean groupExists = my_gs.groupList.checkIfgroupExists(groupname);
			boolean requesterIsOwner = my_gs.groupList.checkOwner(requester, groupname);
			boolean userInGroup = my_gs.groupList.isUserMemberOfGroup(username, groupname);

			if(userExists && requesterExists && groupExists && requesterIsOwner && userInGroup){
				my_gs.groupList.removeMember(username, groupname);
				my_gs.userList.removeGroup(username, groupname);
				token.removeGroup(groupname);
				my_gs.userList.setToken(username, token);
				saveState();

				// generate new key for group
				my_gs.groupList.generateKey(groupname);
				saveState();

				result = true;
			}
		} catch(Exception e){
			System.out.println("\n\t***Failed to remove user from group!***\n");
		}
		return result;
	}

	public SecretKey getGroupKey(String username, String groupname, int pos) {
		SecretKey key = null;
		saveState();
		loadState();

		// check make sure user is member of group
		if (my_gs.groupList.isUserMemberOfGroup(username, groupname)) {
			if (pos < 0) {
				key = my_gs.groupList.getKey(groupname);
			} else {
				key = my_gs.groupList.getKey(groupname, pos);
			}
		}
		saveState();
		return key;
	}

	public int getKeyIndex(String username, String groupname, SecretKey key) {
		int keyIndex = -1;

		// if user is member or owner of group and if group exists and has a key, return the position for that key, otherwise return -1
		if((my_gs.groupList.getKey(groupname) != null) && my_gs.groupList.isUserMemberOfGroup(username, groupname)) {
			keyIndex = my_gs.groupList.getKeyPos(groupname, key);
		}
		return keyIndex;
	}

	public UserToken setHashedDH(String username, byte[] seshKey, UserToken ut){
		ut.setSeshIDkey(seshKey);
	 	ut = addSignatureToToken(ut);
		my_gs.userList.setToken(username, ut);
	 	return ut;
	}

}