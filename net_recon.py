#!/usr/bin/python3

from scapy.all import *
import sys

# Argument Parser
def parse_args(args):
	# Creating a dictionary to return argument parsing results
	options = {'active': False, 'passive': False, 'iface': ""}

	# Check whether the required switches are present and the length of arguments is 4
	if((("-i" in args) or ("--iface" in args)) and ((("-p" in args) or ("--passive" in args)) or (("-a" in args) or ("--active" in args))) and len(args)==4):
		# INTERFACE SWITCH CHECKS
		if("-i" in args):
			iface_index = args.index("-i") + 1
		elif("--iface" in args):
			iface_index = args.index("--iface") + 1
		# Check whether an interface name is correctly provided by the user after -i/--face
		if(args[iface_index].startswith("-")):
			print("Please provide an Interface name\n")
			help()
		else:
			options['iface'] = args[iface_index]

		# ACTIVE/PASSIVE SWITCH CHECKS
		if(("-p" in args) or ("--passive" in args)):
			options['passive'] = True
		# Else check for active scan switch
		elif(("-a" in args) or ("--active" in args)):
			options['active'] = True
	else:
		help()
	# Return the dictionary containing argument parsing results
	return options

# Help menu of the script
def help():
	print("===== HELP MENU =====")
	print("Usage: ./net_recon.py -i/--iface <interface> -a/--active for Active Reconnaissance")
	print("\tor")
	print("\t./net_recon.py -i/--iface <interface> -p/--passive for Passive Scan")
	exit()

# Filer ARP packets for Passive Scan and store them in arp_reply_packets
def filter_arp(arp_reply_packets):
	def packet_handler(pkt):
		# Filtering ARP reply packets which have the opcode as 2 or 'is-at' 
		if 'ARP' in pkt and pkt[ARP].op == 2:
			# Obtaining the source IP and MAC to display and store them
			src_mac = pkt[ARP].hwsrc
			src_ip = pkt[ARP].psrc

			# Storing the packets in arp_reply_packets
			# Appending to list of Source MACs incase of duplicate Source IPs and ensuring that even the MACs do not have duplicate entries
			if(src_ip in arp_reply_packets):
				if src_mac in arp_reply_packets[src_ip]:
					# To remove entries if the same MAC comes up again
					arp_reply_packets[src_ip].remove(src_mac)
				# Appending the MAC at the end to know it is the latest entry
				arp_reply_packets[src_ip].append(src_mac)
			# Creating a list with Source MAC incase of new Source IPs
			else:
				arp_reply_packets[src_ip] = [src_mac]
			print(src_ip + "\t" + src_mac)
	return packet_handler

# Passive Scan Function on interface 'iface'
def passive_scan(iface):
	print("===== Initiating Passive Scan =====")
	# Initializing a dictionary to store ARP reply packets which will contain IP address as the key and list of respective MACs as the value
	arp_reply_packets = dict()

	# Adding exception handling incase sniff() fails
	try:
		# Sniffing the interface and filtering out packets using the 'filter_arp' function in 'prn' field
		# It is possible to filter packets using the 'filter' field in 'sniff' function with value "arp and arp[6:2] == 2" also, instead of filtering packets using prn 
		# In that case we would only store the filtered packets using a function in the 'prn' field or the 'store' field
		sniff(iface=iface, prn=filter_arp(arp_reply_packets))
	except Exception as e:
		print(str(e) + ": " + iface + " " + str(type(e)))
		help()

	# Printing the list of hosts sending the ARP replies as (IP: MAC1 MAC2 .. MACn) where the nth MAC address (MACn) is the latest MAC received for the respective IP without duplicates
	print("\n===== ARP Reply Packets Received =====")
	print("IP\t\tMAC")
	for ip in arp_reply_packets:
		print(ip, end="\t")
		for mac in arp_reply_packets[ip]:
			print(mac, end=" ")
		print()

# Active Recon Function on interface 'iface'
def active_recon(iface_ip):

	# Getting the first 3 octets of the interface network
	network_start_octets = iface_ip.rsplit(".", 1)[0]

	# Initialising an empty list of Active IPs that respond with ICMP replies, discovered during the scan
	active_ips = list()

	print("===== Initiating Active Recon for " + network_start_octets + ".0 =====")
	try:
		# for loop to iterate through the last octet of the network
		for last_octet in range(1, 255):
			# Formatting the destination IP by joining the network first 3 octets and the last octet
			ip = ".".join([network_start_octets, str(last_octet)])
			print("\n\tChecking for IP address: " + ip)

			# Sending out the ICMP request packet with timeout of 1 second and verbosity set to 0 to avoid text clutter
			packet = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)

			# Checking whether an ICMP response is received
			if(packet != None and 'ICMP' in packet and packet[ICMP].type == 0):
				print("\t[+] Reply received from " + ip)
				# if reply received, appending the IP to the list of Active IPs
				active_ips.append(ip)
	# Catching the KeyboardInterrupt exception, so that active_ips list can still be printed for the IPs already scanned
	except KeyboardInterrupt:
		print("\nStopping further scanning...")

	# Printing the final list of Active IPs
	print("\n===== List of Active IPs =====")
	for active_ip in active_ips:
		print(active_ip)


# Main function
def main():
	args = sys.argv
	# Saving the arguments parsed in the dictionary named 'options'
	options = parse_args(args)
	iface = options['iface']

	# Getting the IP address of the interface provided
	iface_ip = get_if_addr(iface)
 	# Verifying the interface provided
	if(iface_ip == "0.0.0.0"):
		print("Provide the correct interface name\n")
		help()

	# Checking whether active or passive scan needs to be initiated
	if(options['passive'] == True):
		print(iface + ": " + iface_ip)
		passive_scan(iface)
	elif(options['active'] == True):
		active_recon(iface_ip)
	else:
		help()


main()
