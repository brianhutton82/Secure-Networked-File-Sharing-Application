/* This list represents the trusted file server fingerprints*/
import java.util.ArrayList;
import java.util.Arrays;
import java.lang.StringBuilder;
import java.security.MessageDigest;
import java.security.PublicKey;


public class FingerprintList implements java.io.Serializable{

    private static final long serialVersionUID = 7600343803563156874L;
    private ArrayList<PublicKey> list = new ArrayList<>();

    public synchronized void addFingerprint(PublicKey fingerprint) {
        list.add(fingerprint);
    }

    public synchronized void deleteFingerprint(PublicKey fingerprint) {
        int loc = list.indexOf(fingerprint);
        if(loc >= 0)
            list.remove(loc);
    }

    public synchronized PublicKey getFingerprint(Integer itr) {
        return list.get(itr);
    }

    public synchronized Integer getLength() {
        return list.size();
    }
    
}
