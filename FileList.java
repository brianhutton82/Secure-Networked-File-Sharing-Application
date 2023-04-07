/* This list represents the files on the server */
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Collections;

public class FileList implements java.io.Serializable {

    /*Serializable so it can be stored in a file for persistence */
    private static final long serialVersionUID = -8911161283900260136L;
    private ArrayList<ShareFile> list;
    public Hashtable<String, Integer> keyIndexes; // <filename, index of key in grouplist used with this file>

    public FileList() {
        list = new ArrayList<ShareFile>();
        keyIndexes = new Hashtable<String, Integer>();
    }

    public synchronized void addFile(String owner, String group, String path) {
        ShareFile newFile = new ShareFile(owner, group, path);
        list.add(newFile);
    }

    public synchronized void addFile(String owner, String group, String path, int keypos) {
        ShareFile newFile = new ShareFile(owner, group, path);
        list.add(newFile);
        keyIndexes.put(path, keypos);
    }

    public synchronized void removeFile(String path) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).getPath().compareTo(path)==0) {
                list.remove(i);
            }
        }
        if(keyIndexes.containsKey(path)){
            keyIndexes.remove(path);
        }
        
    }

    public synchronized boolean checkFile(String path) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).getPath().compareTo(path)==0) {
                return true;
            }
        }
        return false;
    }

    public synchronized ArrayList<ShareFile> getFiles() {
        Collections.sort(list);
        return list;
    }

    public synchronized ShareFile getFile(String path) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).getPath().compareTo(path)==0) {
                return list.get(i);
            }
        }
        return null;
    }

    public synchronized int getKeyPos(String path) {
        int pos = -1;
        if (keyIndexes.containsKey(path)) {
            pos = keyIndexes.get(path);
        }
        return pos;
    }

    public synchronized void storeKeyPos(String filename, int index) {
        if (index >= 0) {
            keyIndexes.put(filename, index);
        }
    }
}
