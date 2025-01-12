/* Main.java
 * 
 * This is the main execution point for the application. It mainly deals with parsing
 * the command line options, setting up the GUI and launching the proxy or pcap deserialization.
 * 
 * 
 */

package sfs2.proxy;


import java.awt.Dimension;
import java.awt.Toolkit;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;


import com.smartfoxserver.v2.entities.data.ISFSObject;
import com.smartfoxserver.v2.protocol.binary.PacketHeader;
import com.smartfoxserver.v2.protocol.serialization.DefaultSFSDataSerializer;
import com.smartfoxserver.v2.protocol.serialization.ISFSDataSerializer;

import sfs2.proxy.SFSDataManipulation.InvalidJSONKey;
import sfs2x.client.SmartFox;
import sfs2x.client.core.SFSIOHandler;


import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.List;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.MessageBox;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.widgets.Button;

import org.json.JSONObject;


public class Main  {
	
	static Logger logger = Logger.getLogger(Main.class.getName());  
    static FileHandler fh; 
    protected Shell shell;
    private static SFSDataManipulation sfsDM = new SFSDataManipulation();

    // Needs to be declared here because Java or something
	private Text textBoxLeft;
	private Text textBoxRight;
    
    ISFSDataSerializer serializer = DefaultSFSDataSerializer.getInstance();
    
    private static ServerThread serverThread = null;
    

	public static void main(String[] args) {
		String logFile, pcapFile, whichMode, outputFilePath, host;
		boolean debug;
		int port;
		CommandLine cmd = parseCommandLine(args);
		

        // Grab the variables from the command line options
        whichMode = cmd.getOptionValue("mode");
        outputFilePath = cmd.getOptionValue("output");
        pcapFile = cmd.getOptionValue("input");
        host = cmd.getOptionValue("host");
        debug = cmd.hasOption( "debug" );
        port = parsePort(cmd.getOptionValue("port"));
        
        // This makes it easier to manage file writing in the decode function when
        // using the d-pcap mode
        if (whichMode.toLowerCase().equals("d-pcap"))
        	debug = true;
        		

        // Set the logFile if it hasn't been set
        if (outputFilePath != null)
        	logFile = outputFilePath;
        else {
        	Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        	SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        	logFile = String.format("/tmp/%s-SFS2proxy.log", sdf.format(timestamp));
        }
        
        prepareLogger(logFile, debug);

        // Execute proxy mode which requires a forwarding host
        if(whichMode.toLowerCase().equals("proxy")) {
        	if(host == null) {
        		logger.info("The forwarding 'host' must be set for proxy mode");
        		System.exit(1);
        	}
        	if(port < 0) {
        		logger.info("Using default port of 9933");
        	}
        	
    		try {
    			Main window = new Main();
    			window.open(host, port);
    			
    		} catch (Exception e) {
    			logger.log( Level.SEVERE, e.toString(), e );
    		}
    		
    	// Execute mode to decode pcap which requires an input PCAP file
        } else if (whichMode.toLowerCase().equals("d-pcap")){
    		try {
    			if(pcapFile == null) {
    				logger.info("Decoding a pcap requires the 'input' argument to be set.");
    				System.exit(1);
    			}
    			else
    				sfsDM.decodePcap(pcapFile, logFile);
    			
    		} catch (PcapNativeException e) {
    			logger.log( Level.SEVERE, e.toString(), e);
    		} catch (NotOpenException e) {
    			logger.log( Level.SEVERE, e.toString(), e);
    		} 
    		
    		
        } else {
        	logger.info(String.format("The mode '%s' does not exist. Choose proxy or d-pcap", whichMode));
        }
	}
	
	// Parse port number from the command line option
	private static int parsePort(String strPort) {
		int port = 9933;
		
        if(strPort == null) {
        	logger.info("No port was passed in, using the default port of 9933");
        } else {
        	
        	// Captures if a non-integer is passed in as the port number
        	try {
        		port = Integer.parseInt(strPort);
        	} catch (NumberFormatException e) {
        		logger.info("The passed in port was not a valid integer");
        		System.exit(1);
        	}
        	
        	// Check that port is in correct range
        	if(0 > port || port > 65535) {
        		logger.info("The passed in port number is not in a valid range");
        		System.exit(1);
        	}
        }
        
		return port;
	}

	//Setup file handler for writing files
	private static void prepareLogger(String logFile, boolean debug) {
		try {
			fh = new FileHandler(logFile, true);
			logger.addHandler(fh);
			
			if (debug) {
				logger.setLevel(Level.ALL);
			}
			
	        SimpleFormatter formatter = new SimpleFormatter();  
	        fh.setFormatter(formatter);
		} catch (IOException e) {
			logger.log( Level.SEVERE, "Error preparing log file.");
			logger.log( Level.SEVERE, e.toString(), e );
		}  
		
	}

	// Parses the command line arguments
	private static CommandLine parseCommandLine(String[] args) {
		Options options = new Options();
		Option mode, output, pcapOption, hostOption;
		CommandLine cmd = null; 
		
		// Prepare each of the possible parameters
        mode = new Option("m", "mode", true, "Start the application in \"proxy\" or \"d-pcap\" mode.");
        mode.setRequired(true);
        options.addOption(mode);

        output = new Option("o", "output", true, "Output file for decoding pcap or for logging proxy requests.");
        options.addOption(output);
        
        pcapOption = new Option("i", "input", true, "Pcap input file for decoding");
        options.addOption(pcapOption);
        
        hostOption = new Option("h", "host", true, "Specify the host to forward traffic to in proxy mode.");
        options.addOption(hostOption);
        
        hostOption = new Option("p", "port", true, "Specify the port to forward traffic to in proxy mode.");
        options.addOption(hostOption);
        
        hostOption = new Option("d", "debug", false, "Print more verbose messages to log file.");
        options.addOption(hostOption);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter helpFormatter = new HelpFormatter();
        

        // Parse out arguments or print help message
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
        	logger.log(Level.FINE, e.toString(), e);
            helpFormatter.printHelp("SFS2Proxy", options);
            System.exit(1);
        }
        
        return cmd;
	}
	
	// Open window
	private void open(String host, int port) {
		Display display = Display.getDefault();
		createContents(host, port);
		
		// Handles closing window with x
	    shell.addListener(SWT.Close, new Listener()
	    {
	        public void handleEvent(Event event)
	        {
	            int style = SWT.APPLICATION_MODAL | SWT.YES | SWT.NO;
	            MessageBox messageBox = new MessageBox(shell, style);
	            messageBox.setText("Information");
	            messageBox.setMessage("Close the shell?");
	            event.doit = messageBox.open() == SWT.YES;
	        }
	    });
		
	    // Launch the GUI
		shell.open();
		shell.layout();
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
		display.dispose();
		System.exit(1);
	}
	

	// Create contents of the window.
	protected void createContents(String host, int port) {
		Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
		
		shell = new Shell();
		shell.setSize((int) (screenSize.width * .9), (int) (screenSize.height * .9));
		shell.setText("SFS2Proxy");
		shell.setLayout(new GridLayout(2, false));
		

		List listLeft = configureList(sfsDM, textBoxLeft);
		listLeft.addSelectionListener(new SelectionAdapter() {
	        public void widgetSelected(SelectionEvent event) {
	    		updateTextBox(listLeft, sfsDM, textBoxLeft);
	        }});

		
	    List listRight = configureList(sfsDM, textBoxRight);
	    listRight.addSelectionListener(new SelectionAdapter() {
	        public void widgetSelected(SelectionEvent event) {
	        	updateTextBox(listRight, sfsDM, textBoxRight);
	        }});
		
	    
		textBoxLeft = createTextBox();
		textBoxRight = createTextBox();
	
		

		Button btnReplay = createButton();
		btnReplay.addSelectionListener(new SelectionAdapter() {
			   @Override
			   public void widgetSelected(SelectionEvent event) {
				   
				   // Grab the JSON and convert it into a SFSObject
				   //TODO: Catch any errors from this
				   handleReplayClick(event, textBoxLeft, listLeft, serverThread.getClientOut(), serverThread.getClientSocket());
			   }
			});
		
		Button btnReplay_1 = createButton();
		btnReplay_1.addSelectionListener(new SelectionAdapter() {
			   @Override
			   public void widgetSelected(SelectionEvent event) {
				   
				   // Grab the JSON and convert it into a SFSObject
				   //TODO: Catch any errors from this
				   handleReplayClick(event, textBoxRight, listRight, serverThread.getServerOut(), serverThread.getServerSocket());
			   }
			});
		
		
		// Start server to wait for connections
		serverThread = new ServerThread(host, 9933, listLeft, listRight);
        new Thread(serverThread).start();
	}
	
	// Prepares a list in the GUI
	private List configureList(SFSDataManipulation sfsDM, Text textBox) {
		List list = new List(shell, SWT.BORDER | SWT.V_SCROLL);
		GridData gd_list = new GridData(GridData.FILL_BOTH);

		list.setItems(new String[] {});
		gd_list.heightHint = 200;
		list.setLayoutData(gd_list);
		
		return list;
	}
		
	// Called to update the text box as the user scrolls
	private void updateTextBox(List list, SFSDataManipulation sfsDM, Text textBox) {
		SmartFox sf = new SmartFox(false);
		SFSIOHandler handler = (SFSIOHandler) sf.getSocketEngine().getIoHandler();
		String item = list.getItem(list.getSelectionIndex());
		ISFSObject sfsObj;
		
		
		try {
			sfsObj = sfsDM.decode(sfsDM.hexStringToByteArray(item), handler);
			textBox.setText(sfsDM.SFSObject2Json(sfsObj).toString(2));
			
		// TODO improve this error catching to be less generic
		} catch (Exception e) {
			logger.log( Level.SEVERE, e.toString(), e);
			textBox.setText("Error decoding data. Check logs for error message.");
		}
		
	}
	
	// Called to handle the click from the replay button
	private void handleReplayClick(SelectionEvent event, Text textBox, List list, DataOutputStream outputStream, Socket socket) {
	       String json = textBox.getText();
	       String item;
	       byte[] b;
	       PacketHeader packetHeader;
	       
	       // Check if socket is open before trying to replay payload 
	       if(outputStream == null) {
	    	   String errMsg = "No open socket to replay payload over.";
	    	   logger.info(errMsg);
	    	   popupError(errMsg, event);
	    	   return;
	       }
	       
	       // Check that an element in the list was selected to avoid crashing here
	       int i = list.getSelectionIndex();
	       if (i == -1) {
	    	   popupError("No item was selected to replay", event);
	    	   return;
	       }
	       
	       // Get the hex string then create a packetHeader with the first byte
	       item = list.getItem(i);
	       b = sfsDM.hexStringToByteArray(item);
	       packetHeader = new PacketHeader(true, (b[0] & 64) > 0, (b[0] & 32) > 0, (b[0] & 16) > 0, (b[0] & 8) > 0);
	       
	       // Try to convert JSON from textbox to SFSObject and send it out over the socket
	       try {
	    	   ISFSObject sfsObj = sfsDM.Json2SFSObject(new JSONObject(json));
		       Replay replay = new Replay(packetHeader, sfsObj, outputStream, socket);
		       new Thread(replay).start();
		       
	       } catch (InvalidJSONKey e) {
	    	   logger.log( Level.SEVERE, e.toString(), e);
	    	   popupError(e.getMessage(), event);
	    	   
	       } catch (Exception e) {
	    	   String errMsg = "Error deserializing JSON from textbox to serialized SFSObject or replaying the request.";
	    	   logger.log( Level.SEVERE, errMsg);
	    	   logger.log( Level.SEVERE, e.toString(), e);
	    	   popupError(errMsg, event);
	       }	
	}
	
	// Popup an error message
	private void popupError(String error, SelectionEvent event) {
		int style = SWT.APPLICATION_MODAL | SWT.OK;
        MessageBox messageBox = new MessageBox(shell, style);
        messageBox.setText("Error");
        messageBox.setMessage(error);
        event.doit = messageBox.open() == SWT.OK;
	}
	

	// Creates the replay buttons for the GUI
	private Button createButton() {
		Button btnReplay = new Button(shell, SWT.NONE);
		btnReplay.setLayoutData(new GridData(SWT.CENTER, SWT.BOTTOM, false, false, 1, 1));
		btnReplay.setText("Replay");
		return btnReplay;
	}

	// Create a text box for the GUI
	private Text createTextBox() {
		GridData gdText = new GridData(GridData.FILL_BOTH);
		gdText.heightHint = 100;
		Text textBox = new Text(shell, SWT.BORDER | SWT.V_SCROLL);
		textBox.setLayoutData(gdText);
		return textBox;
	}

	
}
