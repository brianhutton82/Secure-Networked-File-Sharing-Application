import java.net.Socket;

public abstract class Server {

    // port to connect to this server
    protected int port;
    // name of this server; not used for much right now
    public String name;
    abstract void start();

    public Server(int _SERVER_PORT, String _serverName) {
        port = _SERVER_PORT;
        name = _serverName;
    }


    public int getPort() {
        return port;
    }

    public String getName() {
        return name;
    }

}
