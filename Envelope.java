import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/* envelopes should have authentication code hmac or mac */

public class Envelope implements java.io.Serializable {

    private static final long serialVersionUID = -7726335089122193103L;
    private String msg;
    private ArrayList<Object> objContents = new ArrayList<Object>();
    private int counter;
    private byte[] hmac;
    private Random rng;

    public Envelope(String text) {
        msg = text;
        hmac = null;
        rng = new Random();
        counter = 42;
        //counter = rng.nextInt(100) + 1;
    }

    public String getMessage() {
        return msg;
    }

    public ArrayList<Object> getObjContents() {
        return objContents;
    }

    public void addObject(Object object) {
        objContents.add(object);
    }

    public void incrementCounter(){
        counter++;
    }

    public boolean checkCounter(int val){
        return counter == val;
    }

    public int getCounter() {
        return this.counter;
    }

    public void setCounter(int val){
        this.counter = val;
    }

    public void setHMAC(byte[] data){
            this.hmac = data;
    }

    public byte[] getHMAC(){
        return this.hmac;
    }

    public void removeHMAC(){
        this.hmac = null;
    }
}
