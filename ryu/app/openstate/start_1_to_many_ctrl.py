#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo,SingleSwitchTopo
from mininet.cli import CLI
from mininet.node import UserSwitch,RemoteController
from mininet.term import makeTerm
import os, time
######Starting controller


os.system("xterm -e 'ryu-manager ~/ryu/ryu/app/openstate/forwarding_consistency_1_to_many_ctrl.py'&")



######Starting mininet

mytopo=SingleSwitchTopo(4)
time.sleep(1)
print("\n********************************** HELP *********************************************")
print("\nType \"python ~/ryu/ryu/app/openstate/echo_server.py 200\" in h2's xterm")
print("Type \"python ~/ryu/ryu/app/openstate/echo_server.py 300\" in h3's xterm")
print("Type \"python ~/ryu/ryu/app/openstate/echo_server.py 400\" in h4's xterm")
print("Type \"nc 10.0.0.2 80\" in all h1's xterms\n")
print("In order to test new path selection, close and reopen netcat")
print("\nTo exit type \"ctrl+D\" or exit")
print("*************************************************************************************")
net = Mininet(topo=mytopo,switch=UserSwitch,controller=RemoteController,cleanup=True,autoSetMacs=True,listenPort=6634,autoStaticArp=True)
net.start()
h1,h2,h3,h4  = net.hosts[0], net.hosts[1], net.hosts[2], net.hosts[3]
for i in range(3):
      makeTerm(h1)
makeTerm(h2)
makeTerm(h3)
makeTerm(h4)
CLI(net)
net.stop()
os.system("sudo mn -c")
os.system("kill -9 $(pidof -x ryu-manager)")
