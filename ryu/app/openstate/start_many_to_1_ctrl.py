#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.node import UserSwitch,RemoteController
from mininet.term import makeTerm
import os, time

class MyTopo( Topo ):
  "Simple topology example."

  def __init__( self):
      "Create custom topo."

      # Add default members to class.
      Topo.__init__(self)

      # Add nodes
      
      Host1=self.addHost('h1', ip='10.0.0.1/24')
      Host2=self.addHost('h2', ip='10.0.0.2/24')
      switch1=self.addSwitch('s1')
      switch2=self.addSwitch('s2')
      switch3=self.addSwitch('s3')
      switch4=self.addSwitch('s4')
      switch5=self.addSwitch('s5')

      # Add edges
      self.addLink( Host1, switch1, 1, 1)
      self.addLink( switch1, switch2, 2, 1)
      self.addLink( switch1, switch3, 3, 1)
      self.addLink( switch1, switch4, 4, 1)
      self.addLink( switch2, switch5, 2, 1)
      self.addLink( switch3, switch5, 2, 2)
      self.addLink( switch4, switch5, 2, 3)
      self.addLink( switch5, Host2, 4, 1)

######Starting controller


os.system("xterm -e 'ryu-manager ~/ryu/ryu/app/openstate/forwarding_consistency_many_to_1_ctrl.py'&")



######Starting mininet
topos = { 'mytopo': ( lambda: MyTopo() ) }
mytopo=MyTopo()
time.sleep(1)
print("\n********************************** HELP *********************************************")
print("Type \"python ~/ryu/ryu/app/openstate/echo_server.py 200\" in h2's xterm")
print("Type \"nc 10.0.0.2 200\" in h1's xterm")
print("Watching the tcpdump results, it is possible to see that forwarding consistency is guaranteed\n"
      "In order to test new path selection, close and reopen netcat")
print("\nTo exit type \"ctrl+D\" or exit")
print("*************************************************************************************")
net = Mininet(topo=mytopo,switch=UserSwitch,controller=RemoteController,cleanup=True,autoSetMacs=True,autoStaticArp=True,listenPort=6634)
net.start()
os.system("xterm -e 'tcpdump -i s2-eth1'&")
os.system("xterm -e 'tcpdump -i s3-eth1'&")
os.system("xterm -e 'tcpdump -i s4-eth1'&")
h1,h2  = net.hosts[0], net.hosts[1]
makeTerm(h1)
makeTerm(h2)
CLI(net)
net.stop()
os.system("sudo mn -c")
os.system("kill -9 $(pidof -x ryu-manager)")
