# network-recon

The net_recon.py script/tool allows a user to passively or actively detect hosts on their network. This tool takes in two arguments; A network interface name (e.g. “enp0s3”) and an indicator for active or passive mode. The network interface should be specified using “-i” or “--iface”.  

A user who launches the tool with the “-p” or “—passive” argument will launch the tool in passive mode, where the script will monitor ARP traffic on the given interface and use this traffic to detect IP address and MAC address pairings. IP and MAC addresses collected by the script are printed out to the terminal while the script is running. The passive scan will continue until the user stops the script using ctrl+c. 

A user who launches the tool with the “-a” or “—active” argument will launch the tool in active mode. In active mode the tool will perform a ping sweep. The tool pings every address in the network and detect if a reply was received to determine if that address is active in the network. 
