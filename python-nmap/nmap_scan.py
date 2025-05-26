#!/usr/bin/python3

import nmap

nm = nmap.PortScanner()
print("Enter the IP address of the network")
print("(example: 192.168.1.0/24)")
lan = input(": ")
nm.scan(hosts=lan, arguments='-n -sP -PE') 
for host in nm.all_hosts():
	scanner = nmap.PortScanner()
	scanner.scan(host, "1-1024", '-v -sV')
	print('----------------------------------------------------')
	print('Host : %s (%s)' % (host, scanner[host].hostname()))
	print('State : %s' % scanner[host].state())
	for proto in scanner[host].all_protocols():
		print('----------')
		print('Protocol : %s' % proto)

		lport = scanner[host][proto].keys()
		sorted(lport)
		for port in lport:
			print ('port : %s\tstate : %s' % (port, scanner[host][proto][port]['state']))
