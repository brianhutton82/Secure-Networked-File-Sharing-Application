import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;


// before client logs in, client should verify server, and the server should verify the client

public abstract class Client {

    /* protected keyword is like private but subclasses have access
     * Socket and input/output streams
     */
    protected Socket sock;
    protected ObjectOutputStream output;
    protected ObjectInputStream input;

    public boolean connect(final String server, final int port) {

	System.out.println("attempting to connect");

	boolean result = false;


	// referenced https://github.com/2231-cs1653/server-sample to write this method
	try {
		this.sock = new Socket(server, port);
		this.output = new ObjectOutputStream(sock.getOutputStream());
		this.input = new ObjectInputStream(sock.getInputStream());
		result = true;
	}
	catch(Exception e){
		System.err.println("Error: " + e.getMessage());
		e.printStackTrace(System.err);
	}
	return result;
    }

    public boolean isConnected() {
        if (sock == null || !sock.isConnected()) {
            return false;
        } else {
            return true;
        }
    }

    public void disconnect() {
        if (isConnected()) {
            try {
                Envelope message = new Envelope("DISCONNECT");
                output.writeObject(message);
            } catch(Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
    }
}
