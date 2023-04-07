/* Driver program for FileSharing Group Server */

public class RunGroupServer {

    public static void main(String[] args) {
        if (args.length> 0) {
            try {
                GroupServer server = new GroupServer(Integer.parseInt(args[0]));
                server.start();
            } catch (NumberFormatException e) {
                System.out.println("Enter a valid port number or pass no arguments to use a random port");
            }
        } else {
            java.util.Random rand = new java.util.Random();
            int port = rand.nextInt(5000) + 10000;
            System.out.println("Starting server on random port: " + port);
            GroupServer server = new GroupServer(port);
            server.start();
        }
    }
}
