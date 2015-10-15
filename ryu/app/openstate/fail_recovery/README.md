# Failure Recovery

### Requirements:

Install OpenState (refer to http://openstate-sdn.org/)

	sudo pip install pulp
	sudo pip install networkx
	sudo pip install fnss
	sudo apt-get install python-matplotlib

### Initial setup:

Open 4 ssh terminals into the VM (ssh -X mininet@VM_IP)

In the first terminal type

	cd ~/ryu/ryu/app/openstate/fail_recovery
	sudo ryu-manager fault_tolerance_rest_ff_demo_probing.py


In the remaining VM terminals type

	VM# sudo tcpdump -i s2-eth3
	
	VM# sudo tcpdump -i s2-eth1
	
	VM# sudo watch -n0.5 --color dpctl tcp:127.0.0.1:6635 stats-state -c

From a browser in your host machine open a browser

	http://IP_VM:8080/osfaulttolerance/
	
and click [Open Xterm] for host h1.
In the h1 terminal start a ping to host h6:

	h1# ping -i 0.5 10.0.0.6

### Failure test

From the Wep Application select request (1,6) and bring down link (3,4).

It's possible to notice that packets are sent to interface s2-eth3 at switch 2 and that a new state entry in the state table has appeared.

Every 10 seconds, one packet is forwarded also on the primary path (check tcpdump on interface s2-eth1) to check if the failure has been repaired.

From the Wep Application bring up the link (3,4).

According to the current 'duration' value of the state entry (between 0 and 10), after at most 10 seconds, packets will be forwarded again onto the primary path.
