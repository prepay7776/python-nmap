#!/usr/bin/python3

import socket

def banner(ip, port):
	s = socket.socket()
	s.settimeout(3)
	if s.connect_ex((ip, port)):
		print("timeout")
	else: 
		print(s.recv(1024).decode('utf8'))
	
def main():
	ip = input("Please enter the IP: ")
	port = int(input("Please enter the port: "))
	banner(ip, port)
	
main()

