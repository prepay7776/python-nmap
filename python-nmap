#!/usr/bin/python3

import nmap

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

