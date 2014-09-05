from mininet.topo import Topo

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
		

topos = { 'mytopo': ( lambda: MyTopo() ) }