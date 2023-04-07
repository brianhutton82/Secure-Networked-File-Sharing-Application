/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.text.SimpleDateFormat;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;

import java.util.List;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import java.math.BigInteger;

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

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;


public class FileThread extends Thread {
    private final Socket socket;
    public PublicKey fileServerPublicKey;
    private PrivateKey fileServerPrivateKey;
    public PublicKey clientPublicRSAKey;
    private SecretKey sharedSecretKey;
    public byte[] fingerPrint;
    public static FingerprintList fpList;
    public byte[] SIDkey;

    private BigInteger primeModulus = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d3d73a7" + "749199681ee5b212c9b96bfcdcfa5b20cd5e3fd2044895d609cf9b" + "410b7a0f12ca1cb9a428cc", 16);
    private BigInteger generator = new BigInteger("9494fec095f3b85ee286532b3836fc81a5dda0349b4c239dd387" + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef33c94b" + "f0573bf047a3aca98cdf3b", 16);



    public FileThread(Socket _socket) {
        socket = _socket;
        System.out.println("FT TOP");
    }

    public void run() {
        boolean proceed = true;
        boolean skipEncrypt = false;
        System.out.println("FT RUNNING");

        try {

            System.out.println("*** New FS connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

            // if Diffie-Hellman Key Exchange failed
            if(!establishSecretKey(input, output)){
                System.out.println("Client failed to authenticate");
                System.exit(-1);
            }
            writeFingerprint();
            System.out.println("Fingerprint created and stored.");

            do {

                UserToken token = null;
                String filename = null;
                String remotePath = null;
                ShareFile sf = null;
                byte[] fileContents = null;

                Envelope response = new Envelope("FAIL");
                Envelope e = (Envelope)input.readObject();
                System.out.println("Request received: " + e.getMessage());

                // check if message is encrypted, if so decrypt it
                if(e.getMessage().equals("ENCRYPTED")){
                    byte[] contents = (byte[])e.getObjContents().get(0);
                    e = decryptEnvelope(contents);
                }

                String command = e.getMessage();

                switch(command) {
                    case "CHLNG":
                        byte[] nonce = (byte[])e.getObjContents().get(0);
                        Cipher ciph = Cipher.getInstance("AES", "BC");
                        ciph.init(Cipher.ENCRYPT_MODE, this.sharedSecretKey);
                        byte[] encryptedNonce = ciph.doFinal(nonce);
                        response = new Envelope("RSPS");
                        response.addObject(encryptedNonce);
                        skipEncrypt = true;
                        break;

                    case "LFILES":
                        token = (UserToken)e.getObjContents().get(0);
                        if(!confirmGroupServer(token)) {
                            System.out.println("Unable to verify token, exiting");
                            System.exit(-1);
                        }

                        if(!checkTimeStamp(token)) {
                            System.out.println("Token is outdated, please reset session.");
                            System.exit(-1);
                        }

                        if(!checkSIDkey(token)) {
                            System.out.println("Token is not from this session, disconnecting.");
                            System.exit(-1);
                        }


                        // List to be populated with all files the token owner can access
                        List<String> filesUserCanAccess = new ArrayList<String>();
                        // Get list of all groups that the owner of the token is a member of
                        List<String> tokenOwnerGroups = token.getGroups();
                        // Get list of all files on this server
                        ArrayList<ShareFile> filesOnServer = FileServer.fileList.getFiles();
                        for(ShareFile sharefile : filesOnServer){
                            // check to see if current sharefile group is one of the groups the token owner is a member of
                            if(tokenOwnerGroups.contains(sharefile.getGroup())){
                                // if the token owner is a member of the group associated with the current sharefile
                                // add the path for that file to filesUserCanAccess
                                filesUserCanAccess.add(sharefile.getPath());
                            }
                        }
                        // write list of files user has access to, to the output
                        response = new Envelope("OK");
                        response.addObject(filesUserCanAccess);
                        skipEncrypt = false;
                        break;

                    case "UPLOADF":
                        remotePath = (String)e.getObjContents().get(0);
                        String group = (String)e.getObjContents().get(1);
                        token = (UserToken)e.getObjContents().get(2);
                        fileContents = (byte[])e.getObjContents().get(3);

                        if(!confirmGroupServer(token)) {
                            System.out.println("Unable to verify token, exiting");
                            System.exit(-1);
                        }
                        if(!checkTimeStamp(token)) {
                            System.out.println("Token is outdated, please reset session.");
                            System.exit(-1);
                        }
                        if(!checkSIDkey(token)) {
                            System.out.println("Token is not from this session, disconnecting.");
                            System.exit(-1);
                        }

                        if (!FileServer.fileList.checkFile(remotePath) && token.getGroups().contains(group)) {
                            if (fileContents != null) {
                                File file = new File("shared_files/"+remotePath.replace('/', '_'));
                                file.createNewFile();
                                FileOutputStream fos = new FileOutputStream(file);
                                fos.write(fileContents);

                                System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));
                                response = new Envelope("OK");

                                FileServer.fileList.addFile(token.getSubject(), group, remotePath);
                                fos.close();
                            }
                        } else {
                            System.out.println("Error uploading file.");
                        }

                        skipEncrypt = false;
                        break;

                    case "DOWNLOADF":
                        remotePath = (String)e.getObjContents().get(0);
                        token = (UserToken)e.getObjContents().get(1);
                        if(!confirmGroupServer(token)) {
                            System.out.println("Unable to verify token, exiting");
                            System.exit(-1);
                        }
                        if(!checkTimeStamp(token)) {
                            System.out.println("Token is outdated, please reset session.");
                            System.exit(-1);
                        }
                        if(!checkSIDkey(token)) {
                            System.out.println("Token is not from this session, disconnecting.");
                            System.exit(-1);
                        }

                        sf = FileServer.fileList.getFile("/"+remotePath);
                        if((sf != null) && (token.getGroups().contains(sf.getGroup()))) {
                            fileContents = Files.readAllBytes(Paths.get("shared_files/_"+remotePath.replace('/', '_')));
                            response = new Envelope("OK");
                            response.addObject(fileContents);
                        }
                        else
                        {
                            System.out.println("Error downloading file.");
                        }
                        skipEncrypt = false;
                        break;

                    case "DELETEF":
                        remotePath = (String)e.getObjContents().get(0);
                        token = (UserToken)e.getObjContents().get(1);
                        sf = FileServer.fileList.getFile("/"+remotePath);
                        
                        if (!confirmGroupServer(token)) {
                            System.out.println("Unable to verify token, exiting");
                            System.exit(-1);
                        }
                        if (!checkTimeStamp(token)) {
                            System.out.println("Token is outdated, please reset session.");
                            System.exit(-1);
                        }
                        if(!checkSIDkey(token)) {
                            System.out.println("Token is not from this session, disconnecting.");
                            System.exit(-1);
                        }

                        if((sf != null) && token.getGroups().contains(sf.getGroup())) {
                            File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));
                            if (f.exists() && f.delete()) {
                                System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
                                FileServer.fileList.removeFile("/"+remotePath);
                                response = new Envelope("OK");
                            }
                        }
                        skipEncrypt = false;
                        break;

                    case "STOREKEYPOS":
                        filename = (String)e.getObjContents().get(0);
                        int pos = (int)e.getObjContents().get(1);
                        if (storeKeyIndex(filename, pos)) {
                            response = new Envelope("OK");
                        }
                        skipEncrypt = false;
                        break;

                    case "GETKEYPOS":
                        filename = (String)e.getObjContents().get(0);
                        int index = getKeyIndex(filename);
                        if (index >= 0) {
                            response = new Envelope("OK");
                            response.addObject(index);
                        }
                        skipEncrypt = false;
                        break;

                    case "DISCONNECT":
                        deleteFingerprint();
                        socket.close();
                        proceed = false;
                        break;

                    default:
                        System.out.println("You entered an invalid request!");
                }

                if (!skipEncrypt) {
                    byte[] encryptedResponse = encryptEnvelope(response);
                    response = new Envelope("ENCRYPTED");
                    response.addObject(encryptedResponse);
                }

                output.writeObject(response);

            } while (proceed);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            deleteFingerprint();
            //System.out.println("\n***Exiting file server, goodbye!***\n");
            //System.exit(0);
        }
    }
    

    /* generates public & private key pair for asymmetric encryption
     * returns true if we successfully generate key pair */
    // This also generates a fingerprint
    private boolean serverGenerateKeyPair(){
		boolean result = false;
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			fileServerPublicKey = kp.getPublic();
			fileServerPrivateKey = kp.getPrivate();

			// write group servers public key to file so file server can retrieve it later
			FileOutputStream keyfos = new FileOutputStream("groupserverpubkey");
			keyfos.write(fileServerPublicKey.getEncoded());
			keyfos.close();

			result = true;

            // Generate fingerprint string
            try {
                byte[] publicKeyEncode = fileServerPublicKey.getEncoded();
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(publicKeyEncode.toString().getBytes()); // fingerprint
                this.fingerPrint = md.digest();
            } catch (Exception e) {
                e.printStackTrace();
            }
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
			System.out.println("\n***Sending client File Servers asymmetric public key...***");
			Envelope message = new Envelope("PUBKEY");
			//message.addObject(this.groupServerPublicKey);
			message.addObject(this.fileServerPublicKey.getEncoded());
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
        System.out.println("Attempting to exchange keys FILETHREAD");
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

            // Encrypt server-DH-pub-key with clients RSA public key,
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, this.clientPublicRSAKey);
            PublicKey serverPubKey = (PublicKey)serverPair.getPublic();
            byte[] wrappedDHPubKey = cipher.doFinal(serverPubKey.getEncoded());

            // SIGN using FS private key
            Signature s = Signature.getInstance("SHA384withRSA", "BC");
            s.initSign(fileServerPrivateKey);
            s.update(wrappedDHPubKey);
            byte[] signedDHPubKey = s.sign();

            // send signed DH public , and expected DHPubKey
            message.addObject(signedDHPubKey);
            message.addObject(wrappedDHPubKey);
            output.writeObject(message);
            
            System.out.println("***Awaiting response from client...***");
            // retrieve clients response and get clients public key
            Envelope response = (Envelope)input.readObject();
            System.out.println("***Client response received, sending Client challenge...***");

            if(response.getMessage().equals("DH") && response.getObjContents().get(0) != null){

                // Decrypt clients DH public key using the servers private RSA key
                Cipher ciph = Cipher.getInstance("RSA", "BC");
                ciph.init(Cipher.DECRYPT_MODE, this.fileServerPrivateKey);
                byte[] temp = (byte[])response.getObjContents().get(0);
                byte[] clientDecryptedDHpubKey = ciph.doFinal(temp);
                PublicKey clientKey = (PublicKey)KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(clientDecryptedDHpubKey));

                serverKeyAgree.doPhase(clientKey, true);
                sharedSecretKey = serverKeyAgree.generateSecret("AES[256]");
                createSIDkey(sharedSecretKey);
                System.out.println("FTDHK: " + sharedSecretKey);

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
            cipher.init(Cipher.ENCRYPT_MODE, this.sharedSecretKey);
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
            cipher.init(Cipher.DECRYPT_MODE, this.sharedSecretKey);
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

    private void writeFingerprint()
    {
        String filePrints = "FPrints.bin";
        ObjectInputStream printStream;

        //Open fingerprint file to get fingerprint list
        try {
            FileInputStream fis = new FileInputStream(filePrints);
            printStream = new ObjectInputStream(fis);
            this.fpList = (FingerprintList)printStream.readObject();
            fis.close();
        } catch(FileNotFoundException e) {
            System.out.println("Fingerprint List Does Not Exist.");
        } catch(IOException e) {
            System.out.println("Error reading from Fingerprint List file");
            if(!(this.fpList == null))
            {
                System.exit(-1);
            }
            System.out.println("Fingerprintlist is empty, populating...");
            fpList = new FingerprintList();
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from Fingerprint List file, cnfe");
            System.exit(-1);
        }

        //Add Fingerprint to list, and write to file
        fpList.addFingerprint(fileServerPublicKey);

        ObjectOutputStream outStream;
        try {
            outStream = new ObjectOutputStream(new FileOutputStream(filePrints));
            outStream.writeObject(fpList);
            System.out.println("Succesfully wrote fingerprint,");
            outStream.close();
        } catch(Exception ex) {
            System.err.println("Error attempting to write fingerprint: " + ex.getMessage());
            ex.printStackTrace(System.err);
        }
    }

    private void deleteFingerprint()
    {
        String filePrints = "FPrints.bin";
        ObjectInputStream printStream;

        try {
            FileInputStream fis = new FileInputStream(filePrints);
            printStream = new ObjectInputStream(fis);
            this.fpList = (FingerprintList)printStream.readObject();
        } catch(FileNotFoundException e) {
            System.out.println("Fingerprint List Does Not Exist.");
        } catch(IOException e) {
            System.out.println("Error reading from Fingerprint List file");
            if(!(this.fpList == null))
            {
                System.exit(-1);
            }
            System.out.println("Fingerprintlist is empty, populating...");
            fpList = new FingerprintList();
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from Fingerprint List file, cnfe");
            System.exit(-1);
        }

        fpList.deleteFingerprint(fileServerPublicKey);

        ObjectOutputStream outStream;
        try {
            outStream = new ObjectOutputStream(new FileOutputStream(filePrints));
            outStream.writeObject(fpList);
            System.out.println("Succesfully deleted fingerprint,");
        } catch(Exception ex) {
            System.err.println("Error attempting to delete fingerprint: " + ex.getMessage());
            ex.printStackTrace(System.err);
        }
    }

    public boolean confirmGroupServer(UserToken t){
    	boolean result = true; // In a real-world example, the groupserverpubkey file would be shared out of band between client and server, and this value would be set to false. 
        PublicKey groupServerPublicKey = getGroupServerPubKey(); //This would be uncommented out
    	try {
            Signature s = Signature.getInstance("SHA384withRSA", "BC");
    		byte[] sig = t.getServerSignature(); // extract signature from token
    		s.initVerify(groupServerPublicKey);
    		s.update(t.toString().getBytes()); // add string representation
    		result = s.verify(sig); // verify
    	} catch(Exception e){

    	}
    	return result;
    }

    public PublicKey getGroupServerPubKey(){
    	PublicKey ret = null;
        try {
        byte[] keyBytes = Files.readAllBytes(Paths.get("groupserverpubkey.key"));
        ret =  KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));;
        } catch (Exception e)
        {
            System.out.println("Error reading from groupserverpubkey file, " + e);
        }
        return ret;
    }

    public boolean storeKeyIndex(String filename, int index) {
        boolean result = false;
        if (index >= 0) {
            FileServer.fileList.storeKeyPos(filename, index);
            saveState();
            // check to make sure index was stored
            result = FileServer.fileList.getKeyPos(filename) == index;
        }

        return result;
    }

    public int getKeyIndex(String filename) {
        saveState();
        loadState();
        int index = FileServer.fileList.getKeyPos(filename);
        return index;
    }

    public void saveState() {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
            oos.writeObject(FileServer.fileList);
            oos.close();
        } catch (Exception e) {
            System.out.println("unable to save state of fileList");
        }
    }

    public void loadState() {
        try {
            FileInputStream fileListInStream = new FileInputStream("FileList.bin");
            ObjectInputStream fileListStream = new ObjectInputStream(fileListInStream);
            FileServer.fileList = (FileList)fileListStream.readObject();
            fileListStream.close();
            fileListInStream.close();
        } catch (Exception e) {
            System.out.println("unable to load state of fileList");
        }
    }


    public boolean checkTimeStamp(UserToken token) {

        boolean result = false;
        
        long serverTS = System.currentTimeMillis();
        long clientTS = token.getTimeStamp();

        // if the client time stamp was made more than 12 hours before accessing the file server, fail.
        if(serverTS - clientTS < 43200000)
        {
            result = true;
        }

        return result;
    }

    public void createSIDkey(SecretKey sc) //CHECK
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
            System.out.println("Error generating SID key for server.");
        }
    }

    public boolean checkSIDkey(UserToken token) {
        
        boolean result = false;

        byte[] serverSIDkey = SIDkey; // REMOVE LATER: unneccessary
        byte[] clientSIDkey = token.getSeshIDkey();

        if(Arrays.equals(serverSIDkey, clientSIDkey))
        {
            result = true;
        }

        return result;

    }
}