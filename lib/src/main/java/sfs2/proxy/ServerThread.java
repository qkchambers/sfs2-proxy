package sfs2.proxy;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.swt.widgets.List;


class ServerThread implements Runnable {
	String hostname;
	int port;
	
	List listLeft;
	List listRight;
	
	DataOutputStream clientOut;
	DataOutputStream serverOut;
	
	Socket socket;
	Socket clientSocket;
	
	static Logger logger = Logger.getLogger(Main.class.getName()); 
	
	
	public ServerThread(String hostname, int port, List listLeft, List listRight) {
		this.listLeft = listLeft;
		this.listRight = listRight;
		
		this.hostname = hostname;
		this.port = port;
	}

	public DataOutputStream getServerOut() {
		return this.serverOut;
	}

	@Override
	public void run() {
		startServer(this.hostname, this.port);
	}
	
	public DataOutputStream getClientOut() {
		return this.clientOut;
	}
	
	public Socket getServerSocket() {
		return this.socket;
	}
	
	public Socket getClientSocket() {
		return this.clientSocket;
	}
	
	// Starts the server to listen for clients. The newest client should be the one that the application will be using
	// for replays but the older connections may still be proxying requests
	public void startServer(String hostname, int port) {		
        try (ServerSocket serverSocket = new ServerSocket(port)) {
 
            logger.info("Server is listening on port " + port);
 
            while (true) {
            	// Connection from client
                this.socket = serverSocket.accept();
                logger.info(String.format("New client connected from %s", socket.getInetAddress()));
                
                // Connect to server
                this.clientSocket = new Socket(hostname, port);
                
                this.serverOut = new DataOutputStream(this.socket.getOutputStream());
                DataInputStream serverIn = new DataInputStream(this.socket.getInputStream());  
                
                this.clientOut = new DataOutputStream(this.clientSocket.getOutputStream());
                DataInputStream clientIn = new DataInputStream(this.clientSocket.getInputStream()); 

                // create a new thread object for each combination of sockets
                ClientHandler clientSock = new ClientHandler(serverIn, clientOut, this.listLeft);
                ClientHandler serverSock = new ClientHandler(clientIn, serverOut, this.listRight);
  
                // This thread will handle the client separately
                new Thread(clientSock).start();
                new Thread(serverSock).start(); 
            }
 
        } catch (IOException e) {
        	logger.log(Level.SEVERE, "Error in thread listening for clients");
        	logger.log(Level.SEVERE, e.toString(), e);
        } 
	}
}
