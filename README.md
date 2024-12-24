# sfs2-proxy
This is a proxy developed to intercept the game protocol used in SmartFoxServer 2X. It was created
for a specific app, so it may need some adjustments for other configurations.

To understand more about SmartFoxServer go [here](https://docs2x.smartfoxserver.com/GettingStarted/installation).


# Setup
Download the [installer](https://www.smartfoxserver.com/download/sfs2x#p=installer). From within here you can 
   find the necessary SmartFoxServer libraries and import them into eclipse.
   
   
# Android
To proxy the traffic for an Android device, execute the following commands:
* adb reverse tcp:9934 tcp:9933
* iptables -t nat -A OUTPUT -p tcp -m tcp --dport 9933 -j REDIRECT --to-ports 9934

# TODO
* Add functionality to decrypt traffic
