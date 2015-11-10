#!/usr/bin/python

import os,subprocess,time
import distutils.spawn
from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.node import UserSwitch,RemoteController
from mininet.term import makeTerm

if os.geteuid() != 0:
    exit("You need to have root privileges to run this script")

# Check if hping3 is installed
def is_tool(name):
  return distutils.spawn.find_executable(name) is not None

def wait_for_connection_expiration(max_time=5):
	t = 0
	while t<max_time:
		if 'ESTABLISHED' not in net['h2'].cmd('(netstat -an | grep tcp | grep 10.0.0.2:2000)'):
			return
		print 'Waiting %d sec for connection expiration...' % (max_time-t)
		t += 1
		time.sleep(1)

if not is_tool('hping3'):
		subprocess.call("sudo apt-get -q -y install hping3".split())

# Kill Mininet and/or Ryu
os.system("sudo mn -c 2> /dev/null")
os.system("kill -9 $(pidof -x ryu-manager) 2> /dev/null")

print 'Starting Ryu controller'
os.system('ryu-manager ../ddos/ddos.py 2> /dev/null &')

print 'Starting Mininet'
net = Mininet(topo=SingleSwitchTopo(2),switch=UserSwitch,controller=RemoteController,cleanup=True,autoSetMacs=True,listenPort=6634,autoStaticArp=True)
net.start()

time.sleep(3)

# Start Server @h2 on port 2000
net['h2'].cmd('python ../echo_server.py 2000 &')

###############################################################################
print '\nTest 1: h1 connects to h2 without any ongoing attack'
time.sleep(2)
net['h1'].cmd('(echo "HI!" | nc -q3 -T af11 10.0.0.2 2000) &')

out = ''
attempts = 0
while 'ESTABLISHED' not in out and attempts<5:
	out = net['h2'].cmd('(netstat -an | grep tcp | grep 10.0.0.2:2000)')
	print 'Waiting %d seconds...' % (5-attempts)
	attempts += 1
	time.sleep(1)

if 'ESTABLISHED' in out:
	print 'Test 1: \x1b[32mSUCCESS!\x1b[0m'
else:
	print 'Test 1: \x1b[31mFAIL\x1b[0m'
	exit(1)

###############################################################################
wait_for_connection_expiration(max_time=5)

print '\nTest 2: h1 connects to h2 after an ongoing attack below the the threshold'
net['h1'].cmd('hping3 -S -p 80 -i u200000 -o 28 10.0.0.2 &')
time.sleep(2)
net['h1'].cmd('(echo "HI!" | nc -q3 -T af11 10.0.0.2 2000) &')

out = ''
attempts = 0
while 'ESTABLISHED' not in out and attempts<5:
	out = net['h2'].cmd('(netstat -an | grep tcp | grep 10.0.0.2:2000)')
	print 'Waiting %d seconds...' % (5-attempts)
	attempts += 1
	time.sleep(1)

if 'ESTABLISHED' in out:
	print 'Test 2: \x1b[32mSUCCESS!\x1b[0m'
else:
	print 'Test 2: \x1b[31mFAIL\x1b[0m'
	exit(1)
net['h1'].cmd('kill -9 $(pidof hping3)')

###############################################################################
wait_for_connection_expiration(max_time=5)

print '\nTest 3: h1 connects to h2 after an ongoing attack above the the threshold'
net['h1'].cmd('hping3 -S -p 80 -i u5000 -o 28 10.0.0.2 &')
time.sleep(2)
net['h1'].cmd('(echo "HI!" | nc -q3 -T af11 10.0.0.2 2000) &')

out = ''
attempts = 0
while 'ESTABLISHED' not in out and attempts<5:
	out = net['h2'].cmd('(netstat -an | grep tcp | grep 10.0.0.2:2000)')
	print 'Waiting %d seconds...' % (5-attempts)
	attempts += 1
	time.sleep(1)

if 'ESTABLISHED' in out:
	print 'Test 3: \x1b[31mFAIL\x1b[0m'
	exit(1)
else:
	print 'Test 3: \x1b[32mSUCCESS!\x1b[0m'
net['h1'].cmd('kill -9 $(pidof hping3)')

###############################################################################
time.sleep(2)

print '\nTest 4: h1 connects to h2 before an ongoing attack above the the threshold and continues sending data after the attack'
net['h1'].cmd('((echo "HI"; sleep 5; echo "HI2") | nc -T af11 10.0.0.2 2000) &')
time.sleep(2)
net['h1'].cmd('hping3 -S -p 80 -i u5000 -o 28 10.0.0.2 &')

out = ''
attempts = 0
while 'ESTABLISHED' not in out and attempts<5:
	out = net['h2'].cmd('(netstat -an | grep tcp | grep 10.0.0.2:2000)')
	print 'Waiting %d seconds...' % (5-attempts)
	attempts += 1
	time.sleep(1)

if 'ESTABLISHED' in out:
	print 'Test 4: \x1b[32mSUCCESS!\x1b[0m'
else:
	print 'Test 4: \x1b[31mFAIL\x1b[0m'
	exit(1)
net['h1'].cmd('kill -9 $(pidof hping3)')

# Kill Mininet and/or Ryu
net.stop()
os.system("sudo mn -c 2> /dev/null")
os.system("kill -9 $(pidof -x ryu-manager) 2> /dev/null")