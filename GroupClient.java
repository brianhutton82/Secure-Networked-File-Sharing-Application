/* Implements the GroupClient Interface */

import java.lang.StringBuilder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Base64;
import java.math.BigInteger;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import java.security.Provider;
import java.security.Security;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;

public class GroupClient extends Client implements GroupClientInterface {
    public PublicKey clientPublicKey;
    private PrivateKey clientPrivateKey;
    private SecretKey clientServerKey;
    private byte[] SIDkey;
    public PublicKey gsPubKey;
    private SecretKey hmacKey;
    private BigInteger generator = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7" + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b" + "410b7a0f12ca1cb9a428cc", 16);
    private BigInteger primeModulus = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387" + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b" + "f0573bf047a3aca98cdf3b", 16);
    private int agreedUponCounter = 42; // agreed upon out-of-band by both parties
    private int currentCounterValue = agreedUponCounter;
    static {Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());}

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

    /* generate asymmetric keypair for client
     * return true if we successfully generated keypair */
    public boolean clientGenerateKeyPair(){
    	boolean result = false;
    	try {
    		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
    		kpg.initialize(2048);
    		KeyPair kp = kpg.generateKeyPair();
    		clientPrivateKey = kp.getPrivate();
    		clientPublicKey = kp.getPublic();
    		result = true;
    	} catch(Exception e){
    		e.printStackTrace();
    	}
    	return result;
    }

    // client and server exchange public RSA keys
    public boolean fetchGSpubKey(){
        boolean result = false;
        //int counter = 1;
        if(!clientGenerateKeyPair()){
            System.out.println("\n***Unable to generate Asymmetric keys for client. Exiting!***");
            System.exit(-1);
        }

        // group server sending assymetric public key
        try{
            Envelope gsResponse = (Envelope)input.readObject();
            if(gsResponse.getMessage().equals("PUBKEY")){
                
                // reconstruct group servers public key
                byte [] encodedPub = (byte[])gsResponse.getObjContents().get(0);
                this.gsPubKey = (PublicKey)KeyFactory.getInstance("RSA", "BC").generatePublic(new X509EncodedKeySpec(encodedPub));

                // send group server RSA public key
                Envelope clientResponse = new Envelope("PUBKEY");
                clientResponse.addObject(this.clientPublicKey);
                output.writeObject(clientResponse);

                // ensure server received public key
                Envelope finalResponse = (Envelope)input.readObject();
                if(finalResponse.getMessage().equals("OK")){
                   result = true;
               }
            }
            
        } catch(Exception e){
            System.out.println("\n***Error receiving group servers assymmetric public key, exiting***");
            e.printStackTrace();
        }
        
        return result;
    }

    /* The entire Signed Diffie-Hellman Key Exchange is executed for the client in this method
     * First an exchange of RSA public keys is made between the client and the group server
     * Next, the group server encrypts its DH public key with its RSA private key
     * Then the group server sends its RSA-private-key-encrypted-DH-public-key to the client
     * The client then receives the Envelope containing this encrypted DH public key
     * The client decrypts the encrypted-DH-public key using the group servers previously sent public RSA key
     */
    public boolean establishSecretKey(){
        boolean result = false;
        //int counter = 1;

        if(!fetchGSpubKey()){
            System.out.println("\n***Error receiving group servers asymmetric public key! EXITING");
            System.exit(-1);
        }

    	try {
    		DHParameterSpec dhParameters = new DHParameterSpec(primeModulus, generator);
    		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "BC");
    		kpg.initialize(dhParameters);
    		KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH", "BC");
    		KeyPair clientPair = kpg.generateKeyPair();
    		clientKeyAgree.init(clientPair.getPrivate());

    		// wait for server to initiate exchange
    		Envelope exchange = (Envelope)input.readObject();
    		// server sent public key, send clients public key to server
    		if(exchange.getMessage().equals("DH") && (exchange.getObjContents().get(0) != null)){
    			
                // decrypt DH-public-key using clients private RSA key
                Cipher ciph = Cipher.getInstance("RSA", "BC");
                ciph.init(Cipher.DECRYPT_MODE, this.clientPrivateKey);
                byte[] temp = (byte[])exchange.getObjContents().get(0);
                byte[] gsDecryptedDHpubKey = ciph.doFinal(temp);
                PublicKey serverPublicKey = (PublicKey)KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(gsDecryptedDHpubKey));

    			// generate symmetric key using servers public key
    			clientKeyAgree.doPhase(serverPublicKey, true);
    			clientServerKey = clientKeyAgree.generateSecret("AES[256]");

    			// send server, clients public DH key encrypted with servers public RSA key
    			Envelope clientPubKey = new Envelope("DH");
                PublicKey clientPublicDHKey = (PublicKey) clientPair.getPublic(); // encrypt this key before sending
                ciph.init(Cipher.ENCRYPT_MODE, this.gsPubKey);
                byte[] wrappedDHPubKey = ciph.doFinal(clientPublicDHKey.getEncoded());
                clientPubKey.addObject(wrappedDHPubKey);
    			output.writeObject(clientPubKey);

                Envelope serverFinalResponse = (Envelope) input.readObject();
                if(serverFinalResponse.getMessage().equals("OK")){
                    result = true;
                }
    		}
    	} catch(Exception e){
    		e.printStackTrace();
    	}

    	return result; 
    }

    public UserToken getToken(String username, String password) {
        try {
            UserToken token = null;
            Envelope message = null, response = null;
            
            //Tell the server to return a token.
            message = new Envelope("GET");
            message.addObject(username); //Add user name string
	        message.addObject(password); //Add password

            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            //Get the response from the server
            response = (Envelope)input.readObject();

            // ensure message was not altered
            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            // update local counter and check message counter
            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n\tcurrentCounterValue = " + currentCounterValue + "\n\tcounter in message = " + response.getCounter() + "\n");
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            //Successful response
            if(response.getMessage().equals("OK")) {
                //If there is a token in the Envelope, return it
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

                if(temp.size() == 1) {
                    token = (UserToken)temp.get(0);

                    // verify server signed token
                    try{
                        Signature s = Signature.getInstance("SHA384withRSA", "BC");
                        s.initVerify(gsPubKey);
                        byte[] stringifiedToken = token.toString().getBytes("UTF-8");
                        s.update(stringifiedToken);
                        if(!s.verify(token.getServerSignature())){
                            System.out.println("\n***Server Signature verification failed!***\n");
                            return null;
                        }
                    } catch(Exception e){
                        System.out.println("\n***Token cannot be verified***\n");
                        e.printStackTrace();
                    }
                    return token;
                }
            }

            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public boolean createUser(String username, String password, UserToken token) { 
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("CUSER");
            message.addObject(username); //Add user name string
            message.addObject(token); //Add the requester's token
	        message.addObject(password); // this should be encrypted/hash at some point priort to sending it over the line

            // encrypt
            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            // read server response
            response = (Envelope)input.readObject();

            // ensure message was not altered
            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            // update local counter and check message counter
            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUser(String username, UserToken token) {
        try {
            Envelope message = null, response = null;

            //Tell the server to delete a user
            message = new Envelope("DUSER");
            message.addObject(username); //Add user name
            message.addObject(token);  //Add requester's token

            // encrypt envelope
            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            // retrieve response
            response = (Envelope)input.readObject();

            // ensure message was not altered
            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            // update local counter and check message counter
            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean createGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a group
            message = new Envelope("CGROUP");
            message.addObject(groupname); //Add the group name string
            message.addObject(token); //Add the requester's token
            
            // encrypt envelope
            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            response = (Envelope)input.readObject();

            // ensure message was not altered
            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            // update local counter and check message counter
            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to delete a group
            message = new Envelope("DGROUP");
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            
            // encrypt envelope
            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            response = (Envelope)input.readObject();
            
            // ensure message was not altered
            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            // update local counter and check message counter
            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to return the member list
            message = new Envelope("LMEMBERS");
            message.addObject(group); //Add group name string
            message.addObject(token); //Add requester's token
            
            // encrypt envelope
            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            // retrieve server response
            response = (Envelope)input.readObject();
            
            // ensure message was not altered
            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            // update local counter and check message counter
            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            // decrypt envelope if it is encrypted
            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            //If server indicates success, return the member list
            if(response.getMessage().equals("OK")) {
                return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean addUserToGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to add a user to the group
            message = new Envelope("AUSERTOGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token

            // encrypt envelope
            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            // group servers response
            response = (Envelope)input.readObject();

            // ensure message was not altered
            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            // update local counter and check message counter
            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            // decrypt envelope if it is encrypted
            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to remove a user from the group
            message = new Envelope("RUSERFROMGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token

            // encrypt envelope
            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            // fetch group servers response
            response = (Envelope)input.readObject();

            // ensure message was not altered
            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            // update local counter and check message counter
            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            // decrypt envelope
            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    // client fetches HMAC secret key
    public boolean fetchHMACKey(){
        boolean result = false;
            // group server sending assymetric public key
            try{
                Envelope response = (Envelope)input.readObject();

                // decrypt message first
                if(response.getMessage().equals("ENCRYPTED")){
                    byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                    response = decryptEnvelope(encryptedContents);
                }

                if(response.getMessage().equals("HMACKEY") && (response.getObjContents().get(0) != null)){
                    this.hmacKey = (SecretKey)response.getObjContents().get(0);
                    result = true;
                } else {
                    System.out.println("\n***Unable to retrieve HMAC key... exiting!***\n");
                    System.exit(-1);
                }

                // let server know hmac key was received
                Envelope message = new Envelope("OK");
                
                // encrypt envelope before sending
                byte[] encryptedEnvelopeBytes = encryptEnvelope(message);
                Envelope encryptedEnvelope = new Envelope("ENCRYPTED");
                encryptedEnvelope.addObject(encryptedEnvelopeBytes);
                output.writeObject(encryptedEnvelope);

            } catch(Exception e){
                System.out.println("\n***Error receiving group servers assymmetric public key, exiting***");
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

    public SecretKey getGroupKey(String username, String groupname, int pos) {
        SecretKey key = null;
        Envelope message = null, response = null;

        try {
            message = new Envelope("GETGROUPKEY");
            message.addObject(username);
            message.addObject(groupname);
            message.addObject(pos);

            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            response = (Envelope)input.readObject();

            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n\tcurrentCounterValue = " + currentCounterValue + "\n\tcounter in message = " + response.getCounter() + "\n");
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            if(response.getMessage().equals("OK")) {
                key = (SecretKey)response.getObjContents().get(0);
            }
        } catch (Exception e) {
            System.out.println("\n*** Error fetching groupkey! ***\n");
        }
        return key;
    }


    // return position of key for groupname to store on userList
    public int getKeyIndex(String username, String groupname, SecretKey sk) {
        int pos = -1;
        Envelope message = null, response = null;

        try {
            message = new Envelope("GETKEYPOS");
            message.addObject(username);
            message.addObject(groupname);
            message.addObject(sk);

            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            response = (Envelope)input.readObject();

            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            if(response.getMessage().equals("OK")) {
                pos = (int)response.getObjContents().get(0);
            }
        } catch (Exception e) {
            System.out.println("\n*** Error fetching groupkey index! ***\n");
        }
        return pos;
    }

    public void createSessionIDKey(SecretKey sc)
    {
        //concat sharedSecretKey with || SID, and hash
        byte[] sharedKeyEncode = sc.getEncoded();
        byte[] sidStringEncode = "SID".getBytes();

        byte[] SIDEncode = new byte[sharedKeyEncode.length + sidStringEncode.length];

        System.arraycopy(sharedKeyEncode, 0, SIDEncode, 0, sharedKeyEncode.length);
        System.arraycopy(sidStringEncode, 0, SIDEncode, 0, sidStringEncode.length);

        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            SIDkey = messageDigest.digest(SIDEncode);
        } catch (Exception E){
            System.out.println("Error generating SID key for client.");
        }
    }

    public UserToken storeSessionIDKey(String username, UserToken token)
    {
        Envelope message = null, response = null;
        UserToken newToken = null;

        try{
            message = new Envelope("GETSESSIONIDKEY");
            message.addObject(username);
            message.addObject(SIDkey);
            message.addObject(token);

            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            byte[] calcHMAC = calculateHMAC(encryptedMessage);
            encryptedMessage.setHMAC(calcHMAC);
            output.writeObject(encryptedMessage);

            response = (Envelope)input.readObject();

            if(!checkHMAC(response)){
                System.out.println("\n***Detected alteration in message, exiting!***\n");
                System.exit(-1);
            }

            currentCounterValue++;
            if (!response.checkCounter(currentCounterValue)) {
                System.out.println("\n\tcurrentCounterValue = " + currentCounterValue + "\n\tcounter in message = " + response.getCounter() + "\n");
                System.out.println("\n***Unexpected message order, potential replay attack, exiting!***\n");
                System.exit(-1);
            }

            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            // recieve a token in response, now containing the hashed DH key, acting as a session ID
            if(response.getMessage().equals("OK")) {
                newToken = (UserToken)response.getObjContents().get(0);
                System.out.println("sesOKAY");
            }
        } catch (Exception e) {
            System.out.println("\n*** Error hashing DH key! ***\n");
        }

        return newToken;
    }
}
