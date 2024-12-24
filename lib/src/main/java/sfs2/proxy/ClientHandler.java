package sfs2.proxy;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.SocketException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.List;

import com.smartfoxserver.v2.protocol.binary.PacketHeader;



class ClientHandler extends SFSDataManipulation implements Runnable {

    private final DataOutputStream socketOut;
    private final DataInputStream socketIn;
    private final List list;
    
    static Logger logger = Logger.getLogger(Main.class.getName());  
    
    public ClientHandler(DataInputStream socketIn, DataOutputStream socketOut, List list) throws IOException {
        this.socketOut = socketOut;
        this.socketIn = socketIn; 
        
        this.list = list;
    }

    public void run() {
    	int headerByte;
		
        try {
            while ((headerByte = socketIn.read()) != -1) {
            	// Prepares PacketHeader object to help with rebuilding packet
            	PacketHeader packetHeader = new PacketHeader(true, (headerByte & 64) > 0, (headerByte & 32) > 0, (headerByte & 16) > 0, (headerByte & 8) > 0);
            	super.setExpectedLen(packetHeader, this.socketIn);
            	
            	// Read entire packet and send it to the application server
            	byte[] inputBuf = super.readPayload(packetHeader, this.socketIn);            	
                socketOut.write(inputBuf);
                
                Display.getDefault().asyncExec(new UpdateList(this.list, bytesToHex(inputBuf)));
            }
        } catch (SocketException e) {
        	logger.log(Level.INFO, e.toString(), e);
        } catch (Exception e) {
        	logger.log(Level.SEVERE, e.toString(), e);
        }
        finally {
            try {
                if (socketOut != null) {
                    socketOut.close();
                }
                if (socketIn != null) {
                    socketIn.close();
                }
            } catch (IOException e) {
            	logger.log(Level.SEVERE, e.toString(), e);
            }
        }
    }
    
    // Updates the list (Needs to be called from UI Thread)
    private static class UpdateList implements Runnable {
    	List list;
    	String bytes;
    	
    	public UpdateList(List list, String bytes) {
    		this.list = list;
    		this.bytes = bytes;
    	}

		@Override
		public void run() {
			this.list.add(this.bytes);
		}
    	
    }
    
}
