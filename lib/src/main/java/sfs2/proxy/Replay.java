/* Replay.java
 * 
 * This file is used by the replay button in the GUI. Once the button is clicked, this 
 * thread will launch and replay the currently selected/modified request.
 * 
 * 
 */

package sfs2.proxy;

import java.io.DataOutputStream;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.smartfoxserver.v2.entities.data.ISFSObject;
import com.smartfoxserver.v2.protocol.binary.PacketHeader;


class Replay extends SFSDataManipulation implements Runnable {
    private final DataOutputStream socketOut;
    private final Socket socket;
    PacketHeader packetHeader;
    ISFSObject sfsObj;

    static Logger logger = Logger.getLogger(Main.class.getName());  
   
    
	public Replay(PacketHeader packetHeader, ISFSObject sfsObj, DataOutputStream socketOut, Socket socket) {
		this.packetHeader = packetHeader;
		this.sfsObj = sfsObj;
		this.socketOut = socketOut;
		this.socket = socket;
		
	}

	@Override
	public void run() {
		try {
			logger.info(String.format("Replaying packet to %s", socket.getInetAddress()));
			logger.fine(sfsObj.getDump());
			repeatPayload();
		} catch (Exception e) {
			logger.log( Level.SEVERE, "Error replaying payload");
			logger.log( Level.SEVERE, e.toString(), e);
		}
	}
	
	// Send out SFSObject 
	private void repeatPayload() throws Exception {
		byte[] outputBuffer =  super.createPayload(this.packetHeader, this.sfsObj);
		socketOut.write(outputBuffer);
	}
}
