/* SFSDataManipulation.java
 * 
 * This file is where all of the data handling happens. This code serializes/deserializes
 * the requests, decodes the pcap, handles the packetHeaders and decodes/encodes to JSON
 * for use in the GUIs textbox. 
 * 
 */

package sfs2.proxy;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import com.smartfoxserver.v2.entities.data.ISFSArray;
import com.smartfoxserver.v2.entities.data.ISFSObject;
import com.smartfoxserver.v2.entities.data.SFSArray;
import com.smartfoxserver.v2.entities.data.SFSDataType;
import com.smartfoxserver.v2.entities.data.SFSDataWrapper;
import com.smartfoxserver.v2.entities.data.SFSObject;
import com.smartfoxserver.v2.protocol.binary.DefaultPacketCompressor;
import com.smartfoxserver.v2.protocol.binary.PacketHeader;

import sfs2x.client.SmartFox;
import sfs2x.client.bitswarm.PendingPacket;
import sfs2x.client.core.SFSIOHandler;
import sfs2x.client.util.ByteArray;
import sfs2x.fsm.FiniteStateMachine;

class SFSDataManipulation {
	private final int HEADER_SIZE = 1; 
	private final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	
	static Logger logger = Logger.getLogger(Main.class.getName());  
	
  	// For long data streams integers are used, while for short data streams 
	// a short is used. This code handles this case
    public void setExpectedLen(PacketHeader packetHeader, DataInputStream socketIn) throws IOException {
    	if (packetHeader.isBigSized()) 
    		packetHeader.setExpectedLen(socketIn.readInt());
    	else
    		packetHeader.setExpectedLen(socketIn.readShort());
	}
    
    public void setExpectedLen(PacketHeader packetHeader, byte[] b) throws IOException {
    	byte[] numSize;
    	int size;
    	ByteBuffer wrapped;
    	
    	if (packetHeader.isBigSized()) {
    		numSize = Arrays.copyOfRange(b, 1, 5);
    		wrapped = ByteBuffer.wrap(numSize); 
    		size = wrapped.getInt(); 
    		packetHeader.setExpectedLen(size);
    	}
    	else {
    		numSize = Arrays.copyOfRange(b, 1, 3);
    		wrapped = ByteBuffer.wrap(numSize); 
    		size = wrapped.getShort(); 
    	}
    	packetHeader.setExpectedLen(size);
	}
    

	// creates the complete payload to send over the socket
	public byte[] createPayload(PacketHeader packetHeader, ISFSObject sfsObj) throws Exception {
        byte[] sfsObjBinary = sfsObj.toBinary();
        byte [] payload;
        
        // Compress payload if necessary, based on the header flag
        payload = sfsObjBinary;
        if (packetHeader.isCompressed()) {
        	DefaultPacketCompressor dpc = new DefaultPacketCompressor();
        	payload = dpc.compress(sfsObjBinary);
        }

        // header byte + size of type of length (int or short) + length of the payload
        byte[] allByteArray = new byte[this.HEADER_SIZE + getSizeTypeSize(packetHeader) + payload.length];

        // Create buffer for sending out (headerByte + payload size + payload)
        ByteBuffer tmpBuf = ByteBuffer.wrap(allByteArray);
     
        tmpBuf.put(ByteBuffer.allocate(1).put(encodePacketHeader(packetHeader)).array());
        tmpBuf.put(ByteBuffer.allocate(getSizeTypeSize(packetHeader)).putShort((short)payload.length).array());
        tmpBuf.put(payload);
        
        return tmpBuf.array();
		
	}

	// Reads in the payload based on the header byte and size bytes
	public byte[] readPayload(PacketHeader packetHeader, DataInputStream socketIn) throws IOException {
		int dataSize = packetHeader.getExpectedLen();
		byte[] sizeOfSize;
    	byte[] buf = new byte[dataSize+getSizeTypeSize(packetHeader)+this.HEADER_SIZE];
    	
    	// Create a buffer for the payload size
    	sizeOfSize = ByteBuffer.allocate(getSizeTypeSize(packetHeader)).putShort((short)packetHeader.getExpectedLen()).array();
    	if (packetHeader.isBigSized())
    		sizeOfSize = ByteBuffer.allocate(getSizeTypeSize(packetHeader)).putInt((int)packetHeader.getExpectedLen()).array();
    		
    	
    	// Add the header byte and size of data int/short to buffer
    	buf[0] = encodePacketHeader(packetHeader);
    	for(int i=0; i < getSizeTypeSize(packetHeader); i++) {
    		buf[i+1] = sizeOfSize[i];
    	}
    	
    	// Read the remaining data into the buffer
    	int remaining = dataSize;
    	while(remaining > 0) {
    		buf[dataSize-remaining+getSizeTypeSize(packetHeader)+this.HEADER_SIZE] = (byte)socketIn.read();
    		remaining--;
    	}
    	
    	return buf;
	}
	
    private byte encodePacketHeader(PacketHeader packetHeader) {
    	final int DOCTYPE = 128;
        byte headerByte = 0;
        if (packetHeader.isBinary()) {
            headerByte = (byte) (0 | DOCTYPE);
        }
        if (packetHeader.isEncrypted()) {
            headerByte = (byte) (headerByte | 64);
        }
        if (packetHeader.isCompressed()) {
            headerByte = (byte) (headerByte | 32);
        }
        if (packetHeader.isBlueBoxed()) {
            headerByte = (byte) (headerByte | 16);
        }
        if (packetHeader.isBigSized()) {
            headerByte = (byte) (headerByte | 8);
        }
        return headerByte;
    }
	
	// Return the size of the data type holding the value of the size (int or short)
	private static int getSizeTypeSize(PacketHeader packetHeader) {
		int dataSize = 2;
    	if (packetHeader.isBigSized()) {
    		dataSize =  4;

    	}
    	
		return dataSize;
	}
	
	public class InvalidJSONKey extends Exception { 
		private static final long serialVersionUID = 1001;
	    public InvalidJSONKey(String errorMessage) {
	        super(errorMessage);
	    }
	}
	
	@SuppressWarnings("unchecked")
	private SFSDataWrapper decodeObject(String key, String dataType, JSONObject json) throws ClassNotFoundException, JSONException, InvalidJSONKey {
		SFSDataWrapper dataWrapper;
	    
	    // TODO Unsure if name of arrays (i.e short_array) are correct
	    switch(dataType) {
	    case "null":
	    	dataWrapper = new SFSDataWrapper(SFSDataType.NULL, null);
	    	break;
	    case "bool":
	    	boolean bool = json.getBoolean(key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.BOOL, bool);
	    	break;
	    case "bool_array":
	    	List<Boolean> bool_array = (List<Boolean>) (Object)convert2List(json.getJSONArray(key), "java.lang.Boolean");
	    	dataWrapper = new SFSDataWrapper(SFSDataType.BOOL_ARRAY, bool_array);
	    	break;
	    case "byte":
	    	byte b = (byte)json.getInt(key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.BYTE, Byte.valueOf(b));
	    	break;
	    case "byte_array": 
	    	byte[] byteArray = getByteArray(json, key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.BYTE_ARRAY, byteArray);
	    	break;
	    case "short":
	    	short s = (short)json.getInt(key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.SHORT, Short.valueOf(s));
	    	break;
	    case "short_array":
	    	List<Short> short_array = (List<Short>) (Object)convert2List(json.getJSONArray(key), "java.lang.Short");
	    	dataWrapper = new SFSDataWrapper(SFSDataType.SHORT_ARRAY, short_array);
	    	break;
	    case "int": 
	    	int a = json.getInt(key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.INT, Integer.valueOf(a));
	    	break;
	    case "int_array":
	    	List<Integer> int_array = (List<Integer>) (Object)convert2List(json.getJSONArray(key), "java.lang.Integer");
	    	dataWrapper = new SFSDataWrapper(SFSDataType.INT_ARRAY, int_array);
	    	break;
	    case "long": 
	    	long l = json.getLong(key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.LONG, Long.valueOf(l));
	    	break;
	    case "long_array":
	    	List<Long> long_array = (List<Long>) (Object)convert2List(json.getJSONArray(key), "java.lang.Long");
	    	dataWrapper = new SFSDataWrapper(SFSDataType.LONG_ARRAY, long_array);
	    	break;
	    case "double": 
	    	double d = json.getDouble(key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.DOUBLE, Double.valueOf(d));
	    	break;
	    case "double_array":
	    	List<Double> double_array = (List<Double>) (Object)convert2List(json.getJSONArray(key), "java.lang.Double");
	    	dataWrapper = new SFSDataWrapper(SFSDataType.DOUBLE_ARRAY, double_array);
	    	break;
	    case "float": 
	    	float f = json.getFloat(key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.FLOAT, Float.valueOf(f));
	    	break;
	    case "float_array":
	    	List<Float> float_array = (List<Float>) (Object)convert2List(json.getJSONArray(key), "java.lang.Float");
	    	dataWrapper = new SFSDataWrapper(SFSDataType.FLOAT_ARRAY, float_array);
	    	break;
	    case "utf_string": 
	    	String str = json.getString(key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.UTF_STRING, str);
	    	break;
	    case "utf_string_array":
	    	List<String> utf_string_array = (List<String>) (Object)convert2List(json.getJSONArray(key), "java.lang.String");
	    	dataWrapper = new SFSDataWrapper(SFSDataType.UTF_STRING_ARRAY, utf_string_array);
	    	break;
	    case "text":
	    	String text = json.getString(key);
	    	dataWrapper = new SFSDataWrapper(SFSDataType.TEXT, text);
	    	break;
	    // TODO: Doesn't handle custom classes
	    case "sfs_object": 
	    	ISFSObject sfsObj = Json2SFSObject(json.getJSONObject(key));
	    	dataWrapper = new SFSDataWrapper(SFSDataType.SFS_OBJECT, sfsObj);
	    	break;
	    case "sfs_array": 
	    	ISFSArray sfsArray = Json2SFSArray(json.getJSONArray(key));
	    	dataWrapper = new SFSDataWrapper(SFSDataType.SFS_ARRAY, sfsArray);
	    	break;
	    default:
	    	logger.log( Level.SEVERE, String.format("The data type %s, is unknown", dataType));
	    	throw new InvalidJSONKey(String.format("Invalid JSON key \"%s\". It is not one of the available data types.", dataType));
	    }
	    
	    return dataWrapper;
	}
	

	public ISFSObject Json2SFSObject(JSONObject json) throws InvalidJSONKey, ClassNotFoundException, JSONException {
		ISFSObject sfsObj = new SFSObject();
		
		Iterator<String> keys = json.keys();

		while(keys.hasNext()) {
			String dataType;
		    String keyAndType = keys.next();
		    
		    // Parse out data type from the key
		    Pattern pattern = Pattern.compile("\\((.*?)\\)");
		    Matcher matcher = pattern.matcher(keyAndType);
		    if (matcher.find())
		        dataType = matcher.group(1);
		    else {
		    	logger.warning("Invalid JSON key, missing (data_type)");
		    	throw new InvalidJSONKey(String.format("Invalid JSON key, missing (data_type) in %s", keyAndType));
		    }
		    
		    // Validate that the data type is the first part of the string and then grab the key
		    String remove = String.format("(%s)", dataType);
		    String key;
		    if (keyAndType.contains(remove))
		    	key = keyAndType.replace(remove, "");
		    else {
		    	logger.warning(String.format("%s, is not at the beginning of the JSON key", remove));
		    	return null;
		    }
		    
			sfsObj.put(key, decodeObject(keyAndType, dataType, json));
		}
		
		return sfsObj;
	}



	// Decode a SFSArray 
	private ISFSArray Json2SFSArray(JSONArray jsonArray) throws ClassNotFoundException, JSONException, InvalidJSONKey {
		ISFSArray sfsArray = new SFSArray();
		
		for(int i=0; i < jsonArray.length(); i++) {
			JSONObject json = (JSONObject) jsonArray.get(i);
			Iterator<String> keys = json.keys();
			
			while(keys.hasNext()) {
				String dataType;
				String key = keys.next();
			    
			    // Parse out data type from the key
			    Pattern pattern = Pattern.compile("\\((.*?)\\)");
			    Matcher matcher = pattern.matcher(key);
			    if (matcher.find())
			        dataType = matcher.group(1);
			    else {
			    	logger.warning("Invalid JSON key, missing (data_type)");
			    	return null;
			    }
			    
			    
			    SFSDataWrapper decodedObject = decodeObject(key, dataType, json);
			    sfsArray.add(decodedObject);
			    
			}
		}
		
		return sfsArray;
	}
	
	// Converts the JSON array so that it can be added to the SFSObject
	private List<Object> convert2List(JSONArray jsonArray, String type) throws ClassNotFoundException {
        int arraySize = jsonArray.length();
        List<Object> array = new ArrayList<>();
        
        for (int i = 0; i < arraySize; i++) {
        	
        	Object data = null;
        	switch(type) {
        	case "java.lang.Boolean":
		    	data = jsonArray.getBoolean(i);
	            break;
        	case "java.lang.Short":
        		Integer j = (Integer) jsonArray.getInt(i);
        		data = j.shortValue();
		    	break;
        	case "java.lang.Integer":
		    	data = jsonArray.getInt(i);
		    	break;
		    case "java.lang.Long":
		    	data = (Long) jsonArray.getLong(i);
		    	break;
		    case "java.lang.Float":
		    	data = jsonArray.getFloat(i);
		    	break;
		    case "java.lang.Double":
		    	data = jsonArray.getDouble(i);
		    	break;
		    case "java.lang.String":
		    	data = jsonArray.getString(i);
		    	break;
		    default:
		    	logger.log(Level.SEVERE, String.format("Type %s not found. This should never happen", type));
        	}
        	
        	array.add(data);
        }
        
        return array;
	}

	
	private byte[] getByteArray(JSONObject json, String keyAndType) {
		JSONArray jsonArray = json.getJSONArray(keyAndType);
		byte[] byteArray = new byte[jsonArray.length()];

        if (jsonArray != null) {   
            for (int i=0;i<jsonArray.length();i++){     
            	byteArray[i] = ((byte)jsonArray.getInt(i));
            }   
        }
		
		return byteArray;
	}



	public JSONObject SFSObject2Json(ISFSObject sfsObj) {
		JSONObject json = new JSONObject();

        Iterator<String> it = sfsObj.getKeys().iterator();
        while (it.hasNext()) {
        	String newKey;
            String key = it.next();
            SFSDataWrapper wrapper = sfsObj.get(key);
            newKey = String.format("(%s)%s", wrapper.getTypeId().name().toLowerCase(), key);
            
            // TODO add functionality for parsing custom classes
            if (wrapper.getTypeId() == SFSDataType.SFS_OBJECT) {
            	json.put(newKey, SFSObject2Json(sfsObj.getSFSObject(key)));
            } else if (wrapper.getTypeId() == SFSDataType.SFS_ARRAY) {
            	json.put(newKey, SFSArray2Json(sfsObj.getSFSArray(key)));
            } else {
            	//TODO See if this handles all possible cases (unsure about byte[] data types)
            	json.put(newKey, wrapper.getObject());
            }
        }
        
        return json;
	}





	private Object SFSArray2Json(ISFSArray sfsArray) {
		JSONArray json = new JSONArray();
		Iterator<SFSDataWrapper> iter = sfsArray.iterator();
		
		while (iter.hasNext()) {
			String newKey;
			SFSDataWrapper wrapper = iter.next();
			newKey = String.format("(%s)", wrapper.getTypeId().name().toLowerCase());
            JSONObject o = new JSONObject();
            
            //TODO add functionality for parsing custom classes
            if (wrapper.getTypeId() == SFSDataType.SFS_OBJECT) {
            	
            	json.put(o.put(newKey, SFSObject2Json((ISFSObject) wrapper.getObject())));
            } else if (wrapper.getTypeId() == SFSDataType.SFS_ARRAY) {
            	json.put(o.put(newKey, SFSArray2Json((ISFSArray) wrapper.getObject())));
            } else {
            	//TODO See if this handles all possible cases (unsure about byte[] data types)
            	json.put(o.put(newKey, wrapper.getObject()));
            }
		}
		
		return json;
	}
	
	// Decode TCP packet data by using the smartfox jar
	public ISFSObject decode(byte[] buf, SFSIOHandler handler) {
		ISFSObject sfsObj = null;
		ByteArray data = new ByteArray(buf);
		
		try {
			logger.fine(bytesToHex(buf));
			handler.onDataRead(data);
			
			
			// Used to access private variable (pendingPacket)
			Field f=SFSIOHandler.class.getDeclaredField("pendingPacket");
		    f.setAccessible(true);
		    PendingPacket pp = (PendingPacket)f.get(handler);
		  
		    // Makes the private fsm variable accessible
			Field f1=SFSIOHandler.class.getDeclaredField("fsm");
		    f1.setAccessible(true);
		    FiniteStateMachine fsm = (FiniteStateMachine)f1.get(handler);
		    
		    // Checks the fsm state, this is needed to handle data that is contained in multiple tcp packets
		    if (fsm.getCurrentState() == 0) {
		    	// Turns the bytes into an SFSObject which can then be used
				sfsObj = SFSObject.newFromBinaryData(pp.getBuffer().getBytes());
				logger.fine(sfsObj.getDump());
		    }	
		
		} catch (Exception e) {
			logger.log(Level.SEVERE, e.toString(), e);
		} 

		return sfsObj;
	}
	
	// Decodes a pcap file into more human readable stuff
		public void decodePcap(String pcapFilename, String logfile) throws PcapNativeException, NotOpenException {
			final PcapHandle handle;
	        Packet p = null;
			String filter = "tcp port 9933";
			
			SmartFox sf = new SmartFox(false);
			SFSIOHandler handler = (SFSIOHandler) sf.getSocketEngine().getIoHandler();
			handle = Pcaps.openOffline(pcapFilename);

			// Filter for TCP packets on port 9933
			handle.setFilter(filter, BpfCompileMode.OPTIMIZE);


			// Loop through and grab each packet
	        while(true) {
	        	try {
					p = handle.getNextPacketEx();
				} catch (EOFException e) {
					logger.log( Level.INFO, "Reached the end of the PCAP");
					break;
				} catch (PcapNativeException e) {
					logger.log( Level.SEVERE, e.toString(), e );
				} catch (TimeoutException e) {
					logger.log( Level.SEVERE, e.toString(), e );
				} catch (NotOpenException e) {
					logger.log( Level.SEVERE, e.toString(), e );
				}
	        	
	        	// Break out of loop after all packets have been read
	            if (p == null) {
	                break;
	            }
	            
	            // Get a TCP packet with a payload and decode it
	            TcpPacket tcpPacket = p.get(TcpPacket.class);
	            if (tcpPacket.getPayload() != null) {
	            	byte[] data = tcpPacket.getPayload().getRawData();
	            	decode(data, handler);
	            }
	        }	
		}
	
	public String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	public byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
}
