# DOS detection

### Requirements:

Install OpenState (refer to http://openstate-sdn.org/)

sudo apt-get install hping3

### Initial setup:

Open two ssh terminals into the VM (ssh -X mininet@VM_IP)

In the first terminal start the Ryu Controller application:

	cd ~/ryu/ryu/app/openstate/ddos
	ryu-manager ddos.py

In the second terminal create a small Mininet network with 2 hosts and 1 switch:

	sudo mn --topo single,2 --arp --mac --switch user --controller remote
	
From Mininet open 3 terminals (2 on host h1 and 1 on host h2)
	
	mininet> xterm h1 h1 h2

From Mininet you can display the state table

	mininet> sh watch -n1 --color dpctl tcp:127.0.0.1:6634 stats-state table=all tcp_dst=2000 -c

NB: to avoid having an huge state table visualization, we are just showing connections towards TCP port 2000 (even if the attack will be carried out towards TCP port 80).
Since we are detecting attacks towards h2 host in general (not towards a particular TCP port) the choice of the destination port will not affect our tests.

Finally open an Echo Server on host h2 (TCP port 2000)

	h2# python ~/ryu/ryu/app/openstate/echo_server.py 2000

## Test 1 - normal conditions

From host h1 open a new TCP connection towards Echo Server on h2 ("-T af11" sets DSCP field to 10)

	h1# nc -T af11 10.0.0.2 2000

In the netcat terminal type something and press ENTER (or just keep pressed ENTER key for some seconds).
h1 shows replies from h2 correctly.
The state table 1 is still empty because no attack is in progress, so this connection is in DEF state (and flows in DEF state are not visible).
Close netcat client with CTRL+C

## Test 2 - normal conditions (2)

From the two h1 terminals open some TCP connections towards h2 ("-o 28" and "-T af11" set DSCP field to 10)

	h1# hping3 -S -p 80 -i u200000 -o 28 10.0.0.2
	h1# nc -T af11 10.0.0.2 2000

In the netcat terminal type something and press ENTER (or just keep pressed ENTER key for some seconds).
Once again the state table 1 is empty and h1 shows replies from h2.
The meter has been set to 10 pkt/s (1 pkt every 100ms), but since we are not exceeding the threshold (hping3 create one new connection every 200ms), our netcat connections works.
The "-S" options allows to send just SYN pkt without establishing a complete TCP connections.
Connections are created towards host h2 on TCP destination port 80 with a random TCP source port (that's why we filtered the dpctl output!)

Close both netcat and hping3 with CTRL+C.

## Test 3 - attack conditions (1)

From one h1 terminal open some TCP connections towards h2

	h1# hping3 -S -p 80 -i u5000 -o 28 10.0.0.2

After some seconds stop hping3 with CTRL+C.
It is possible to check that 95% of new connections have been dropped: we are creating one new connection every 5ms, while the meter allows at most a new connection every 100 ms. Thus only 5% will not be dropped.
Close hping3 with CTRL+C.

## Test 4 - attack conditions (2)

From the two h1 terminals open some TCP connections towards h2.

	h1# nc -T af11 10.0.0.2 2000
	h1# hping3 -S -p 80 -i u5000 -o 28 10.0.0.2
	
The execution order is extremely important so the suggestion is:
-copy&paste the first command (nc) without pressing ENTER
-copy&paste the second command (hping3) without pressing ENTER
-press ENTER in the nc terminal and rapidly press ENTER in the hping3 terminal
-within 30 seconds keep pressed ENTER in nc terminal

Only 5% of attacking connections are not dropped (as in test 3), while the netcat connection is not interrupted  because it has been established before the attack!

If we wait more than 30 seconds, the netcat connection expires (we have configured a 30 seconds idle timeout) and any message sent (or any ENTER long pressure) in netcat would be considered a new connection and would be dropped because established after the attack. It's possible to notice a new connection in state 1 in the state table!

Close both netcat and hping3 with CTRL+C.

## Test 5 - attack conditions (3)

By repeating test 4 with the order of nc and hping3 inverted, we can see that netcat connection is immediately dropped because the attack has already started.

If we close hping3 with CTRL+C and we retry

	h1# nc -T af11 10.0.0.2 2000
	
the connection is correctly established :)
