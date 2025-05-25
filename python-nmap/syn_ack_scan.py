#!/usr/bin/python3

import nmap

'''
This script conducts a SYN/ACK scan to determine the state of TCP ports on a target system. 
It operates by sending a SYN (synchronize) packet to the target port. 
If the port is open, the target responds with a SYN/ACK (synchronize-acknowledge) packet. 
The scanning host then sends an RST (reset) packet to terminate the connection, thus completing the three-way handshake. 
This technique is often referred to as "half-open scanning" because it doesn't fully establish a TCP connection. 
Using python-nmap, a SYN/ACK scan can be performed and the results parsed for analysis. 
If a SYN/ACK is received, it indicates that the port is open and listening for connections. 
If a RST is received, it indicates the port is closed. If there is no response, or an ICMP error message is received, 
the port is considered filtered, meaning that a firewall or other network device is likely blocking the connection attempt.
'''

nm = nmap.PortScanner()
print("Enter the IP address of the network")
print("(example: 192.168.1.0/24)")
lan = input(": ") 
nm.scan(hosts=lan)

for host in nm.all_hosts():
	print('----------------------------------------------------')
	print('Host : %s (%s)' % (host, nm[host].hostname()))
	print('State : %s' % nm[host].state())
	for proto in nm[host].all_protocols():
	    print('----------')
	    print('Protocol : %s' % proto)

	    lport = nm[host][proto].keys()
	    sorted(lport)
	    for port in lport:
        	print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

