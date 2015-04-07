#!/usr/bin/env python 

""" 
An echo server that uses select to handle multiple clients at a time.
Command-line parameter: port=listening port
""" 

import select 
import socket 
import sys 


if len(sys.argv)!=2:
    print("You need to specify a listening port!")
    sys.exit()

host = '' 
port = int(sys.argv[1])
backlog = 5 # maximum number of queued connections
size = 1024  # buffer size
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
server.bind((host,port)) 
server.listen(backlog) 
input = [server,sys.stdin] 
running = 1
print("Press any key to stop the server...")
while running:
    # The Python select module allows an application to wait for input from multiple sockets at a time.
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
            data = "[from h"+sys.argv[1][0]+"]: " 
            data = data+s.recv(size) 
            if data:
                try: 
                    s.send(data)
                except socket.error, e: 
                    s.close()
                    input.remove(s)
                    break
            else: 
                s.close() 
                input.remove(s) 
server.close()
