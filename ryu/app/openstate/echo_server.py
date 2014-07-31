#!/usr/bin/env python 

""" 
An echo server that uses select to handle multiple clients at a time. 
Entering any line of input at the terminal will exit the server. 
""" 

import select 
import socket 
import sys 

host = '' 
port = int(sys.argv[1])
backlog = 5 
size = 1024 
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
server.bind((host,port)) 
server.listen(backlog) 
input = [server,sys.stdin] 
running = 1 
while running: 
    inputready,outputready,exceptready = select.select(input,[],[]) 

    for s in inputready: 

        if s == server: 
            # handle the server socket 
            client, address = server.accept() 
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