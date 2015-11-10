#!/usr/bin/python

import os,subprocess,time
from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.node import UserSwitch,RemoteController
from mininet.term import makeTerm

if os.geteuid() != 0:
    exit("You need to have root privileges to run this script")

# Kill Mininet and/or Ryu
os.system("sudo mn -c 2> /dev/null")
os.system("kill -9 $(pidof -x ryu-manager) 2> /dev/null")

print 'Starting Ryu controller'
os.system('ryu-manager ../maclearning.py 2> /dev/null &')

print 'Starting Mininet'
net = Mininet(topo=SingleSwitchTopo(4),switch=UserSwitch,controller=RemoteController,cleanup=True,autoSetMacs=True,listenPort=6634,autoStaticArp=True)
net.start()

time.sleep(6)

drop_perc = net.pingAll(2)
if drop_perc == 0.0:
	print 'Ping between all hosts: \x1b[32mSUCCESS!\x1b[0m'
else:
	print 'Ping between all hosts: \x1b[31mFAIL\x1b[0m'
	exit(1)

t = 0
while t<15:
	print 'Waiting %d sec for timeout expiration...' % (15-t)
	t += 1
	time.sleep(1)

net['h2'].cmd('(tcpdump -n -l &> /tmp/tcpdumplog.h2) &')
net['h3'].cmd('(tcpdump -n -l &> /tmp/tcpdumplog.h3) &')
time.sleep(3)
net['h1'].cmd('ping -c1 10.0.0.2')
time.sleep(3)

# Processes are shared: kill command from h2 kills also tcpdump in h1!
net['h2'].cmd("kill -SIGINT $(pidof tcpdump)")

with open("/tmp/tcpdumplog.h2","r") as myfile:
    h2data=myfile.read()
with open("/tmp/tcpdumplog.h3","r") as myfile:
    h3data=myfile.read()

if 'ICMP echo request' in h2data and 'ICMP echo reply' in h2data and 'ICMP echo request' in h3data and 'ICMP echo reply' not in h3data:
	print '\nPing from h1 to h2 (request should be in broadcast, reply in unicast): \x1b[32mSUCCESS!\x1b[0m'
else:
	print '\nPing from h1 to h2 (request should be in broadcast, reply in unicast): \x1b[31mFAIL\x1b[0m'
	exit(1)

# Kill Mininet and/or Ryu
net.stop()
os.system("sudo mn -c 2> /dev/null")
os.system("kill -9 $(pidof -x ryu-manager) 2> /dev/null")