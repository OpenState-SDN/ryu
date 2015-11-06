#!/usr/bin/env python 

""" 
An echo server that uses select to handle multiple clients at a time. 
Entering any line of input at the terminal will exit the server. 
""" 

import select 
import socket 
import sys 

if len(sys.argv)!=2:
    print("You need to specify a listening port!")
    sys.exit()

host = '' 
port = int(sys.argv[1])
backlog = 5 
size = 1024 
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
server.bind((host,port)) 
server.listen(backlog) 
input = [server,sys.stdin] if sys.stdin.isatty() else [server]
running = 1 
print("Press any key to stop the server...")
while running: 
    inputready,outputready,exceptready = select.select(input,[],[]) 

    for s in inputready: 

        if s == server: 
            # handle the server socket 
            client, address = server.accept()
	    print("New client at "+address[0]+":"+str(address[1]))     
            input.append(client) 

        elif s == sys.stdin: 
            # handle standard input 
            junk = sys.stdin.readline() 
            running = 0 

        else: 
            # handle all other sockets 
            data = s.recv(size) 
            if data: 
                s.send("[from h"+sys.argv[1][0]+"]: "+str(data) )
            else: 
                s.close() 
                input.remove(s) 
server.close()
