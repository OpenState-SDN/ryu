#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo,SingleSwitchTopo
from mininet.cli import CLI
from mininet.node import UserSwitch,RemoteController
from mininet.term import makeTerm
import os, time
######Starting controller


os.system("xterm -e 'ryu-manager ~/ryu/ryu/app/openstate/link_protection.py'&")

######Starting mininet

mytopo=SingleSwitchTopo(4)
time.sleep(1)
print("\n********************************** HELP *********************************************")
print("\nType \"ping 10.0.0.2\" in h1's first xterm")
print("Type \"ping 10.0.0.3\" in h1's second xterm")
print("In order to change the outport from 2 to 3 and viceversa\n")
print("Type \"nc -w 1 10.0.0.1 33333\" in h2's xterm or \"nc -w 1 10.0.0.1 22222\" in h3's xterm")
print("\nTo exit type \"ctrl+D\" or exit")
print("*************************************************************************************")
net = Mininet(topo=mytopo,switch=UserSwitch,controller=RemoteController,cleanup=True,autoSetMacs=True,listenPort=6634,autoStaticArp=True)
net.start()
h1,h2,h3,h4  = net.hosts[0], net.hosts[1], net.hosts[2], net.hosts[3]

makeTerm(h1)
makeTerm(h1)
makeTerm(h2)
makeTerm(h3)

CLI(net)
net.stop()
os.system("sudo mn -c")
os.system("kill -9 $(pidof -x ryu-manager)")
