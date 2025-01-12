## About
[SmartFoxServer](https://www.smartfoxserver.com/) is a comprehensive SDK for rapidly developing multiplayer games and applications. The server communicates with the client using a custom binary protocol. SFS2Proxy is a tool for deserializing traffic used for the SmartFoxServer 2x. The tool can be used for deserializing data from a PCAP file or as a proxy to intercept and replay requests.

## Installation
Precompiled JAR files can be grabbed from the release section. 

## Building
For building and making modifications to the code, import the GitLab project into Eclipse. There are also a few JARs that need to be imported into the project. Download the SFS2Server client API from [here](https://www.smartfoxserver.com/download/sfs2x#p=client). From the downloaded zip, import all of the JARs into Eclipse. There is another JAR used for drawing the GUI, this can be downloaded from the [Eclipse website](https://download.eclipse.org/eclipse/downloads/index.html#Stable_Builds). To import into Eclipse,
Project > Properties > Java Build Path, then select Libraries and Add External JARs. Then navigate to the previously downloaded JAR files to load them into the project. This should clear up all of the dependencies.

## Usage
usage: SFS2Proxy
 -d,--debug          Print more verbose messages to log file.
 -h,--host <arg>     Specify the host to forward traffic to in proxy mode.
 -i,--input <arg>    Pcap input file for decoding
 -m,--mode <arg>     Start the application in "proxy" or "d-pcap" mode.
 -o,--output <arg>   Output file for decoding pcap or for logging proxy
                     requests.
 -p,--port <arg>     Specify the port to forward traffic to in proxy mode.
 
SFS2Proxy has 2 modes of operation. The d-pcap mode is used for loading a pcap file and 
decrypting its contents. This mode requires an input file. The other mode is proxy. This mode defaults to port 9933 (use --port to specify different port) and requires a host to forward the network traffic to. The output defaults to /tmp/DATE-SFS2Proxy.log but this can be changed with the output argument. For more detailed output, such as a log for all decoded packets, use the --debug flag. 

# Android
To proxy the traffic for an Android device, execute the following commands:
* adb reverse tcp:9934 tcp:9933
* iptables -t nat -A OUTPUT -p tcp -m tcp --dport 9933 -j REDIRECT --to-ports 9934

## TODO
* Handle encryption.
* Include the packetHeader checkboxes in the UI (allowing it to be changed).
* Include time stamp next to each request.
* Allow backing up to file and reopening from that state.
* Allow for staying at most recent request.
* Allow setting the port/host for decrypting a pcap.
* Unsure if all the data types are labeled correctly in decodeObject of SFSDataManipulation.
* Doesn't handle deserializing custom classes


## Notes About the Tool
 * Is there a better way to represent the data to be replayed?
 * Might be possible to cause a DoS in the parser through nested SFSObjects. 
 * The proxy only works for 1 client at a time
 * Converting byte array to sfsObject then back to byte array creates different sequence of bytes. This doesn't appear to cause any issues.
 * NullPointerExceptions get thrown when deserializing some SFSObjects. This happens because there are associated commands to be executed but the proxy does not need to handle these because the game is, so this doesn't impact anything.
 * The JSON keys for modifying a request are in the form (data_type)key. If a key uses '(' or ')', the parser will fail
