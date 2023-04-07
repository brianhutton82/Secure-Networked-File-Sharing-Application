/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;

import java.lang.StringBuilder;
import java.math.BigInteger;

import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import java.util.List;
import java.util.Base64;

import java.security.Provider;
import java.security.Security;
import java.security.PublicKey;
import java.security.SecureRandom;
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
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.RandomGenerator;


public class FileClient extends Client implements FileClientInterface {
    public PublicKey fClientPublicKey;
    private PrivateKey fClientPrivateKey;
    private SecretKey fClientServerKey;
    public PublicKey fsPubKey;
    private final BigInteger primeModulus = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d3d73a7" + "749199681ee5b212c9b96bfcdcfa5b20cd5e3fd2044895d609cf9b" + "410b7a0f12ca1cb9a428cc", 16);
    private final BigInteger generator = new BigInteger("9494fec095f3b85ee286532b3836fc81a5dda0349b4c239dd387" + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef33c94b" + "f0573bf047a3aca98cdf3b", 16);

    static {Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());}

    public byte[] encryptEnvelope(Envelope message){
        byte[] encryptedEnvelope = null;
        try{
            Cipher cipher = Cipher.getInstance("AES", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, this.fClientServerKey);
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
            cipher.init(Cipher.DECRYPT_MODE, this.fClientServerKey);
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

    public boolean checkFingerprint(String port)
    {
        boolean ret = true; // In a real-world example, the FPrints file would be shared out of band between client and server, and this value would be set to false.
        String filePrints = "FPrints.bin";
        ObjectInputStream printStream;
        FingerprintList fpList = new FingerprintList();
        PublicKey fsFingerprint; 

        //Get fingerprint from list, generate comparison hash, compare
        try {
            FileInputStream fis = new FileInputStream(filePrints);
            if(fis.available() > 0)
            {
                printStream = new ObjectInputStream(fis);
                fpList = (FingerprintList)printStream.readObject();
                
                for(int i = 0; i < fpList.getLength(); i++)
                {
                    fsFingerprint = fpList.getFingerprint(i);
                    
                    if(!fsPubKey.equals(fsFingerprint))
                    {
                        ret = false;
                        System.out.println("Fingerprint read and rejected");
                    }
                    else
                    {
                        ret = true;
                        System.out.println("Fingerprint read and approved");
                    }
                }
            }
        } catch(FileNotFoundException e) {
            System.out.println("Fingerprint List Does Not Exist. FC");
        } catch(IOException e) {
            System.out.println("Error reading from Fingerprint List file, " + e);
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from Fingerprint List file " + e);
            System.exit(-1);
        }

        return ret;
    }


    public boolean delete(String filename, UserToken token) {
        Envelope message = null, response = null;
        
        // Generate path of file to be deleted
        String remotePath;
        if (filename.charAt(0)=='/') {
            remotePath = filename.substring(1);
        } else {
            remotePath = filename;
        }

        // Tell server to delete that path
        message = new Envelope("DELETEF"); 
        message.addObject(remotePath);
        message.addObject(token);

        // Encrypt envelope
        byte[] encryptedEnvelope = encryptEnvelope(message);
        Envelope encryptedMessage = new Envelope("ENCRYPTED");
        encryptedMessage.addObject(encryptedEnvelope);

        try {
            output.writeObject(encryptedMessage);

            // Retrieve/decrypt response
            response = (Envelope)input.readObject();
            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            if (response.getMessage().compareTo("OK")==0) {
                System.out.printf("File %s deleted successfully\n", filename);
            } else {
                System.out.printf("Error deleting file %s (%s)\n", filename, response.getMessage());
                return false;
            }
        } catch (IOException e1) {
            e1.printStackTrace();
        } catch (ClassNotFoundException e1) {
            e1.printStackTrace();
        }

        return true;
    }


    public byte[] download(String sourceFile, String destFile, UserToken token) {
        byte[] result = null;

        if (sourceFile.charAt(0)=='/') {
            sourceFile = sourceFile.substring(1);
        }

        try {

            Envelope message = null, response = null;

            message = new Envelope("DOWNLOADF");
            message.addObject(sourceFile);
            message.addObject(token);
            
            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            output.writeObject(encryptedMessage);

            response = (Envelope)input.readObject();
            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            if (response.getMessage().equals("OK")) {
                
                result = (byte[])response.getObjContents().get(0);
            }
            
        } catch (Exception e) {
            System.out.println("\n***ERROR DOWNLOADING FILE!***\n");
        }
        return result;
    }


    @SuppressWarnings("unchecked")
    public List<String> listFiles(UserToken token) {
        try {
            Envelope message = null, e = null;
            //Tell the server to return the member list
            message = new Envelope("LFILES");
            message.addObject(token); //Add requester's token

            // encrypt envelope, and send
            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            output.writeObject(encryptedMessage);

            // retrieve/decrypt response
            e = (Envelope)input.readObject();
            if(e.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])e.getObjContents().get(0);
                e = decryptEnvelope(encryptedContents);
            }

            //If server indicates success, return the member list
            if(e.getMessage().equals("OK")) {
                return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }


    public boolean upload(String sourceFile, String destFile, String group, UserToken token, byte[] fileContents) {
    
        boolean result = false;

        if (destFile.charAt(0)!='/') {
            destFile = "/" + destFile;
        }

        try {
            Envelope message = null, response = null;

            message = new Envelope("UPLOADF");
            message.addObject(destFile);
            message.addObject(group);
            message.addObject(token);
            message.addObject(fileContents);

            byte[] encryptedEnvelope = encryptEnvelope(message);
            Envelope encryptedMessage = new Envelope("ENCRYPTED");
            encryptedMessage.addObject(encryptedEnvelope);
            output.writeObject(encryptedMessage);

            response = (Envelope)input.readObject();
            if (response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            if (response.getMessage().equals("OK")) {
                result = true;
            }
        } catch (Exception e) {
            System.out.println("\n*** UPLOAD FAILED ***\n");
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
    		fClientPrivateKey = kp.getPrivate();
    		fClientPublicKey = kp.getPublic();
    		result = true;
    	} catch(Exception e){
    		e.printStackTrace();
    	}
    	return result;
    }

    // client and server exchange public RSA keys
    public boolean fetchFSpubKey(){
        boolean result = false;

        if(!clientGenerateKeyPair()){
            System.out.println("\n***Unable to generate Asymmetric keys for client. Exiting!***");
            System.exit(-1);
        }

        // file server sending assymetric public key
        try{
            Envelope fsResponse = (Envelope)input.readObject();
            if(fsResponse.getMessage().equals("PUBKEY")){
                //this.gsPubKey = (PublicKey)gsResponse.getObjContents().get(0);

                // reconstruct file servers public key
                byte [] encodedPub = (byte[])fsResponse.getObjContents().get(0);
                this.fsPubKey = (PublicKey)KeyFactory.getInstance("RSA", "BC").generatePublic(new X509EncodedKeySpec(encodedPub));

                // send file server RSA public key
                Envelope clientResponse = new Envelope("PUBKEY");
                clientResponse.addObject(this.fClientPublicKey);
                output.writeObject(clientResponse);

                // ensure server received public key
                Envelope finalResponse = (Envelope)input.readObject();
                if(finalResponse.getMessage().equals("OK")){
                }   result = true;
            }
        } catch(Exception e){
            System.out.println("\n***Error receiving file servers assymmetric public key, exiting***");
            e.printStackTrace();
        }
        
        return result;
    }

    public boolean establishSecretKey(){
        boolean result = false;

        if(!fetchFSpubKey()){
            System.out.println("\n***Error receiving file servers asymmetric public key! EXITING");
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
    		if(exchange.getMessage().equals("DH") 
                && exchange.getObjContents().get(0) != null
                && exchange.getObjContents().get(1) != null){
    			
                // get FS signed DH public key, and check signature
                byte[] signedServerDHKey = (byte[])exchange.getObjContents().get(0);
                byte[] wrappedServerDHKey = (byte[])exchange.getObjContents().get(1);
                try {
                    Signature s = Signature.getInstance("SHA384withRSA", "BC");
                    s.initVerify(fsPubKey);
                    s.update(wrappedServerDHKey);
                    if(!s.verify(signedServerDHKey)){
                        System.out.println("\n***File Server Signature verification failed!***\n");
                        return false;
                    }
                    else{
                        System.out.println("\n***File Server successfully verified!***\n");
                    }
                } catch(Exception e){
                    System.out.println("\n***File server cannot be verified***\n");
                    e.printStackTrace();
                }

                // decrypt DH-public-key using clients private RSA key
                Cipher ciph = Cipher.getInstance("RSA", "BC");
                ciph.init(Cipher.DECRYPT_MODE, this.fClientPrivateKey);
                //byte[] temp = (byte[])exchange.getObjContents().get(0);
                byte[] fsDecryptedDHpubKey = ciph.doFinal(wrappedServerDHKey);
                PublicKey serverPublicKey = (PublicKey)KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(fsDecryptedDHpubKey));

    			// generate symmetric key using servers public key
    			clientKeyAgree.doPhase(serverPublicKey, true);
    			fClientServerKey = clientKeyAgree.generateSecret("AES[256]");

    			// send server, clients public DH key encrypted with servers public RSA key
    			Envelope clientPubKey = new Envelope("DH");
                PublicKey clientPublicDHKey = (PublicKey) clientPair.getPublic(); // encrypt this key before sending
                ciph.init(Cipher.ENCRYPT_MODE, this.fsPubKey);
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

    public boolean issueChallenge()
    {
        try {
            //Generate challenge
            byte[] nonce = new byte[16];
            new SecureRandom().nextBytes(nonce);

            Envelope message = null, env = null;
            //Give the group server our challenge
            message = new Envelope("CHLNG");
            message.addObject(nonce);
            output.writeObject(message);

            env = (Envelope)input.readObject();
            System.out.println("Response received: " + env.getMessage());

            byte[] encNonce = null;
            if(env.getMessage().equals("RSPS")) {
                encNonce = (byte[])env.getObjContents().get(0);
            }

            byte[] decryptedContents = null;
            try {
                Cipher cipher = Cipher.getInstance("AES", "BC");
                cipher.init(Cipher.DECRYPT_MODE, this.fClientServerKey);
                decryptedContents = cipher.doFinal(encNonce);
            } catch(Exception e){
                System.out.println("\n***Unable to decrypt!***");
                e.printStackTrace();
            }

            if(Arrays.equals(nonce, decryptedContents))
            {
                System.out.println("Challenge successful!");
                return true;
            }
            
            return false;

        } catch (Exception chEx) {
            System.out.println("Challenge failed: " + chEx);
            return false;
        }
    }

    public boolean storeKeyIndex(String filename, int index) {
        boolean result = false;
        try {
            Envelope message = null, response = null;
            message = new Envelope("STOREKEYPOS");
            message.addObject(filename);
            message.addObject(index);

            byte[] encryptedEnvelope = encryptEnvelope(message);
            message = new Envelope("ENCRYPTED");
            message.addObject(encryptedEnvelope);

            output.writeObject(message);

            response = (Envelope)input.readObject();
            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            if (response.getMessage().equals("OK")) {
                result = true;
            }

        } catch (Exception e) {
            System.out.println("\n*** Error storing key index!, index value: " + String.valueOf(index) + " ***\n");
        }
        return result;
    }

    public int getKeyIndex(String filename){
        int index = -1;
        try {

            Envelope message = null, response = null;
            message = new Envelope("GETKEYPOS");
            message.addObject(filename);

            byte[] encryptedEnvelope = encryptEnvelope(message);
            message = new Envelope("ENCRYPTED");
            message.addObject(encryptedEnvelope);
            output.writeObject(message);

            response = (Envelope)input.readObject();

            if(response.getMessage().equals("ENCRYPTED")){
                byte[] encryptedContents = (byte[])response.getObjContents().get(0);
                response = decryptEnvelope(encryptedContents);
            }

            if (response.getMessage().equals("OK")) {
                index = (int)response.getObjContents().get(0);
            }
        } catch(Exception e){
            System.out.println("\n***Error fetching index for key!***\n");
        }
        return index;
    }

    public SecretKey getSessionDHkey(){
        return fClientServerKey;
    }

}

