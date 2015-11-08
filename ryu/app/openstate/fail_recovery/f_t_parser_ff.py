'''
f_t_parser.py               -->     OpenState version
f_t_parser_m_f.py           -->     OpenState version with multiple faults
f_t_parser_ctrl.py          -->     OpenFlow version: FastFailover detection, in case of fault packets are sent to CTRL in any case and the CTRL reroute them and installs new rules
f_t_parser_ctrl_drop.py     -->     OpenFlow version: real FastFailover (local detour exploiting FF). in case local detour is not available, packets are dropped while waiting the CTRL
f_t_parser_ctrl_flags.py    -->     OpenFlow version: detection using OS'Global States (instead of FF). The same as f_t_parser_ctrl_drop.py: in case local detour is not available, packets are sent to the CTRL. The CTRL installs the new rules but does not reroute received packets (it drops them).
f_t_parser_ff.py            -->     OpenState version exploiting OF's Fast Failover instead of OS's Global States
'''
from __future__ import division
from pulp import Amply
import json
import cPickle as pickle
import pprint
import array
import networkx as nx
from xml.dom import minidom
import matplotlib.pyplot as plt
import os.path
import hashlib
import fnss
import os,glob
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController,UserSwitch
from mininet.term import makeTerm
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osproto
import ryu.ofproto.openstate_v1_0_parser as osparser
import time
from sets import Set

#from collections import Counter

hh = hashlib.md5(open('results.txt').read()).hexdigest()

if not os.path.exists('./tmp'):
    os.makedirs('./tmp')

flow_entries_dict = dict()
flow_stats_dict = dict()
group_entries_dict = dict()
group_ID = dict()
requests = dict()
faults = dict()
net = None
G = None
pos = None
host = None
switches = None
mapping = None
mn_topo = None
mn_topo_ports = {}

def parse_ampl_results(filename='results.txt'):

    data = Amply("""
    set PrimaryPath{REQUESTS};
    set DetourPath{NODES, NODES, REQUESTS};
    param DetectNode{NODES, NODES, REQUESTS};
    """)

    data.load_file(open(filename))

    requests = dict()
    faults = dict()
    stats = dict()
    pp_edges = dict()

    print "Parsing requests..."
    for i in data.PrimaryPath:
        rid = int(i)
        pp = [int(x) for x in data.PrimaryPath[rid]]
        pp_edge = (pp[0], pp[-1])
        requests[pp_edge] = {
            'pp_edge': pp_edge,
            'primary_path': pp,
            'faults': dict()}
        pp_edges[rid] = pp_edge
        #print rid, pp_edge, pp

    for i in data.DetectNode.data:

        na = int(i)
        val_na = data.DetectNode.data[na]

        for j in val_na:

            nb = int(j)
            val_nb = val_na[j]

            # if (nb > na):
            #     continue
            # if (nb == 0):
            #     fault_type = 'node'
            #     fid = "N-" + str(na)
            # else:
            #     fault_type = 'link'
            #     fid = "L-" + str(na) + "-" + str(nb)

            for d in val_nb:
                rid = int(d)

                if na < nb:
                    fault_edge = (na, nb)
                else:
                    fault_edge = (nb, na)

                pp_edge = pp_edges[rid]
                pp = requests[pp_edge]['primary_path']

                detect_node = int(val_nb[rid])
                dp = [int(x) for x in data.DetourPath.data[na][nb][rid]]
                redirect_node = dp[0]

                # Fw back path is the sequence of node from detect to redirect node (included)
                idx_d = pp.index(detect_node)
                idx_r = pp.index(redirect_node)
                if(idx_d - idx_r == 0):
                    fw_back_path = None
                else:
                    fw_back_path = pp[idx_r:idx_d + 1]

                fault = {'detect_node': detect_node,
                         'redirect_node': redirect_node,
                         'detour_path': dp,
                         'fw_back_path': fw_back_path}
                # For each request, we populate the corresponding faults...
                requests[pp_edge]['faults'][fault_edge] = fault

                # And viceversa, for each fault, we populate the requests...
                if fault_edge not in faults:
                    faults[fault_edge] = {
                        'requests': {}}

                faults[fault_edge]['requests'][pp_edge] = {
                    'primary_path': pp,
                    'detect_node': detect_node,
                    'redirect_node': redirect_node,
                    'detour_path': dp,
                    'fw_back_path': fw_back_path}

    with open('./tmp/' + hh + '-requests.p', 'wb') as fp:
        pickle.dump(requests, fp)
    with open('./tmp/' + hh + '-faults.p', 'wb') as fp:
        pickle.dump(faults, fp)

    return requests, faults


def print_node_stats(ds=None):

    stats = list()

    for node in range(1, 28):

        s = {'primary_path': 0, 'detour_path': 0,
             'detect_node': 0, 'redirect_node': 0, 'fw_back_path': 0}
        for rid in ds:
            d = ds[rid]
            if(node in d['primary_path']):
                s['primary'] += 1
            for fault_id in d['faults']:
                fault_scenario = d['faults'][fault_id]

                if(node in fault_scenario['detour_path'][1:-1]):
                    s['detour_path'] += 1
                if(node == fault_scenario['detect_node']):
                    s['detect'] += 1
                if(node == fault_scenario['redirect_node']):
                    s['redirect'] += 1
                if(fault_scenario['redirect_node'] == fault_scenario['detect_node']):
                    continue
                idx_d = d['primary_path'].index(
                    fault_scenario['detect_node'])
                idx_r = d['primary_path'].index(
                    fault_scenario['redirect_node'])
                if(idx_d - idx_r <= 1):
                    continue
                if(node in d['primary_path'][idx_r + 1:idx_d]):
                    s['fw_back'] += 1

        stats.append(s)

    print node, stats


def parse_network_xml(filename='network.xml'):

    global G, pos, hosts, switches, mapping

    G = nx.Graph()
    pos = dict()
    # We need to keep track of which nodes are switches and which one are hosts, as G has nodes only
    switches = []
    hosts = []

    xmldoc = minidom.parse(filename)
    # Nodes creation
    itemlist = xmldoc.getElementsByTagName('node')
    for s in itemlist:
        n = s.attributes['id'].value
        # Remove the N char at the beginning
        n = int(n[1:])
        switches.append(n)
        G.add_node(n)
        x = s.getElementsByTagName('x')[0].firstChild.data
        y = s.getElementsByTagName('y')[0].firstChild.data
        pos[n] = [float(x), float(y)]

    # Links creation
    itemlist = xmldoc.getElementsByTagName('link')
    for s in itemlist:
        src = s.getElementsByTagName('source')[0].firstChild.data
        src = int(src[1:])
        trg = s.getElementsByTagName('target')[0].firstChild.data
        trg = int(trg[1:])
        G.add_edge(src, trg)

    # mapping is a dict() that associates node's number with their name
    mapping = dict([(switches[i], "s%s" % str(switches[i])) for i in range(len(switches))])
    
    # Hosts creation: if there's a demand NX->NY => 2 hosts hX and hY are created and linked to switches sX and sY
    itemlist = xmldoc.getElementsByTagName('demand')
    for s in itemlist:
        src = s.getElementsByTagName('source')[0].firstChild.data
        src = int(src[1:])
        trg = s.getElementsByTagName('target')[0].firstChild.data
        trg = int(trg[1:])
        count = len(switches)+len(hosts)
        if "h"+str(src) not in mapping.values():
            hosts.append(count+1)
            mapping = dict(mapping.items() + [(count+1, "h%s" % str(src))])
            G.add_node(count+1)
            G.add_edge(src,count+1)
        count = len(switches)+len(hosts)
        if "h"+str(trg) not in mapping.values():
            hosts.append(count+1)
            mapping = dict(mapping.items() + [(count+1, "h%s" % str(trg))])
            G.add_node(count+1)
            G.add_edge(trg,count+1)
    print(mapping)
    return G, pos, hosts, switches, mapping


def networkx_to_mininet(G, hosts, switches, mapping):
    # Conversion from NetworkX topology into FNSS topology
    fnss_topo = fnss.Topology(G)

    # G is a NetworkX Graph() and fnss_topo is a FNSS Topology(): hosts and switches are indistinguishable.
    # We exploit 'mapping' returned from parse_network_xml() for nodes role differentiation.
    # We can't use fnss.adapters.to_mininet() because we need a customized nodes relabeling.
    # TODO link capacities!! http://fnss.github.io/doc/core/_modules/fnss/adapters/mn.html

    # Conversion from FNSS topology into Mininet topology
    nodes = set(fnss_topo.nodes_iter())
    hosts = sorted(set(hosts))
    switches = sorted(set(switches))

    hosts = set(mapping[v] for v in hosts)
    switches = set(mapping[v] for v in switches)

    if not switches.isdisjoint(hosts):
        raise ValueError('Some nodes are labeled as both host and switch. '
                         'Switches and hosts node lists must be disjoint')
    if hosts.union(switches) != switches.union(hosts):
        raise ValueError('Some nodes are not labeled as either host or switch '
                         'or some nodes listed as switches or hosts do not '
                         'belong to the topology')
    
    fnss_topo = nx.relabel_nodes(fnss_topo, mapping, copy=True)

    global mn_topo
    mn_topo = Topo()
    for v in switches:
        mn_topo.addSwitch(str(v))
    for v in hosts:
        mn_topo.addHost(str(v))
    for u, v in fnss_topo.edges_iter():
            params = {}
            mn_topo.addLink(str(u), str(v), **params)
    return mn_topo


def add_flow_entry(flow_entries_dict,datapath_id,flow_entry):
    if datapath_id not in flow_entries_dict.keys():
       flow_entries_dict = dict(flow_entries_dict.items() + [(datapath_id, [flow_entry])])
    else:
       flow_entries_dict[datapath_id].append(flow_entry)
    return flow_entries_dict

def update_flow_stats(flow_stats_dict,datapath_id,flow_type):
    # global counter
    if 0 not in flow_stats_dict.keys():
        flow_stats_dict = dict(flow_stats_dict.items() + [(0, {})])
        flow_stats_dict[0]['tot_flows']=0
        flow_stats_dict[0]['primary']=0
        flow_stats_dict[0]['detour']=0
        flow_stats_dict[0]['fw_back']=0
        flow_stats_dict[0]['detect&red']=0
        flow_stats_dict[0]['redirect_only']=0
        flow_stats_dict[0]['detect_only']=0
        flow_stats_dict[0]['group']=0

    if datapath_id not in flow_stats_dict.keys():
        flow_stats_dict = dict(flow_stats_dict.items() + [(datapath_id, {})])
        flow_stats_dict[datapath_id]['tot_flows']=0
        flow_stats_dict[datapath_id]['primary']=0
        flow_stats_dict[datapath_id]['detour']=0
        flow_stats_dict[datapath_id]['fw_back']=0
        flow_stats_dict[datapath_id]['detect&red']=0
        flow_stats_dict[datapath_id]['redirect_only']=0
        flow_stats_dict[datapath_id]['detect_only']=0
        flow_stats_dict[datapath_id]['group']=0

    flow_stats_dict[datapath_id]['tot_flows']+=1
    flow_stats_dict[datapath_id][flow_type]+=1

    #global counter
    flow_stats_dict[0]['tot_flows']+=1
    flow_stats_dict[0][flow_type]+=1

    return flow_stats_dict
    
def add_group_entry(group_entries_dict,datapath_id,group_ID,bucket):
    if datapath_id not in group_entries_dict.keys():
       group_entries_dict = dict(group_entries_dict.items() + [(datapath_id, {group_ID: [bucket]})])
    else:
        if group_ID not in group_entries_dict[datapath_id].keys():
            group_entries_dict[datapath_id][group_ID]=[bucket]
        else:
            group_entries_dict[datapath_id][group_ID].append(bucket)
    return group_entries_dict

def print_flow_stats(flow_stats_dict):

    for nodes in flow_stats_dict:
        if nodes!=0:
            print("\nNODE "+str(nodes)+": ")
            for rule_type in flow_stats_dict[nodes].items():
                if rule_type[0]!='tot_flows':
                    s=str(rule_type[0]+"="+str(rule_type[1])).ljust(16)
                    s+="\t("
                    s+="%.2f" % (rule_type[1]*100/flow_stats_dict[nodes]['tot_flows'])
                    s+="%)"
                    print(s)
            print("-->TOT FLOWS="+str(flow_stats_dict[nodes]['tot_flows']))
    print("----------------------------------")
    print("GLOBAL COUNTERS\n")
    for rule_type in flow_stats_dict[0].items():
        if rule_type[0]!='tot_flows':
            s=str(rule_type[0]+"="+str(rule_type[1])).ljust(16)
            s+="\t("
            s+="%.2f" % (rule_type[1]*100/flow_stats_dict[0]['tot_flows'])
            s+="%)"
            print(s)
    print("-->TOT FLOWS="+str(flow_stats_dict[0]['tot_flows']))


def generate_flow_entries_dict(GUI=False):

    global requests, faults
    global G, pos, hosts, switches, mapping
    global mn_topo
    global net
    global mn_topo_ports

    if (os.path.isfile('./tmp/last_results_hash')):
        f=open('./tmp/last_results_hash','r')
        if (str(hh)!=f.read()):
            print('Erasing figs folder...')
            f.close()
            files = glob.glob('./figs/*')
            for f in files:
                os.remove(f)
            f=open('./tmp/last_results_hash','w+')
            f.write(str(hh))
            f.close()
    else:
        f=open('./tmp/last_results_hash','w+')
        f.write(str(hh))
        f.close()
        print('Erasing figs folder...')
        f.close()
        files = glob.glob('./figs/*')
        for f in files:
            os.remove(f)

    if (os.path.isfile('./tmp/' + hh + '-requests.p') and os.path.isfile('./tmp/' + hh + '-faults.p')):
        print 'Loading chached requests, faults...'
        requests = pickle.load(open('./tmp/' + hh + '-requests.p'))
        faults = pickle.load(open('./tmp/' + hh + '-faults.p'))
    else:
        print 'Parsing ampl results (it may take a while)...'
        requests, faults = parse_ampl_results()

    print len(requests), 'requests loaded'
    print len(faults), 'faults loaded'

    print "Building network graph from network.xml..."
    G, pos, hosts, switches, mapping = parse_network_xml()
    print 'Network has', len(switches), 'switches,', G.number_of_edges()-len(hosts), 'links and', len(hosts), 'hosts'

    print "NetworkX to Mininet topology conversion..."
    mn_topo = networkx_to_mininet(G, hosts, switches, mapping)

    '''
    Mininet API 2.1.0ps
    mn_topo.ports = {'s3': {'s2': 1, 's4': 2}, 's2': {'s3': 1, 's1': 2, 's5': 3}, ...}

    Mininet API 2.2.0
    mn_topo.ports = {'s3': {1: ('s2', 1), 2: ('s4', 1)}, 's2': {1: ('s3', 1), 2: ('s1', 1), 3: ('s5', 1)}, ...}

    Our parser is based on old API. mn_topo_ports is an adapted version of mn_topo.ports according to the old API
    '''
    for k in mn_topo.ports:
        mn_topo_ports[k]={}
        for k2 in mn_topo.ports[k]:
            mn_topo_ports[k][ mn_topo.ports[k][k2][0] ] = k2
    
    print "Cleaning previous Mininet instances..."
    os.system('sudo mn -c 2> /dev/null')
    net = Mininet(topo=mn_topo, link=TCLink, controller=RemoteController, switch=UserSwitch, cleanup=True,autoSetMacs=False,listenPort=6634)
    print "Starting Mininet topology..."
    net.start()

    # Setup of MAC and IP 
    for i in range(len(net.hosts)):
        host_name = str(net.hosts[i])
        host_number = host_name[1:]
        mac_str = int_to_mac_str(int(host_number))
        ip_str = int_to_ip_str(int(host_number))
        net.hosts[i].setMAC(mac_str,'h'+host_number+'-eth0')
        net.hosts[i].setIP(ip_str,8,'h'+host_number+'-eth0')
        #makeTerm(net.hosts[i])

    if not GUI:
        s = raw_input("\n\x1B[32mInsert host numbers (separated by spaces) to open xterm: \x1B[0m")
        host_indexes = map(int, s.split())
        if len(host_indexes)>0:
            for i in host_indexes:
                if 'h'+str(i) in net:
                    makeTerm(net['h'+str(i)])
    
    # Setup of Static ARP Entries
    for src in net.hosts:
        for dst in net.hosts:
            if src != dst:
                src.setARP(ip=dst.IP(), mac=dst.MAC())

    # Flow entries creation

    # flow_entries_dict is a dict() that associates nodes with their flow entries
    global flow_stats_dict
    global flow_entries_dict
    global group_entries_dict
    global group_ID
    # fault_ID is a dict() that associates faults with an ID
    fault_ID = dict()

    # Associate req (A,B) and fault (X,Y) with a progressive number, starting from 1.
    # group_IDs are used as group entries index
    i=1
    for r in requests:
        for f in requests[r]['faults']:
            group_ID[(r,f)]=i
            group_ID[(r,(f[1],f[0]))]=i
            i+=1

    # Associate fault (X,Y) with a progressive number, starting from 1. fault_IDs are used for MPLS tags and flow states.
    # Actually tag and state values will be shifted by 16 because MPLS label values 0-15 are reserved.
    for i in range(1,len(faults.keys())+1):
        fault_ID = dict(fault_ID.items() + [(faults.keys()[i-1], i)])

    for i in range(len(requests)):
        request = requests.keys()[i]
        print "Processing REQUEST %d/%d: %s" %(i+1,len(requests),request)
        #detect nodes for this request
        detect_nodes=Set([])
        redirect_nodes=Set([])
        for y in range(len(requests[request]['faults'])):
            detect_nodes.add(requests[request]['faults'].items()[y][1]['detect_node'])
        for y in range(len(requests[request]['faults'])):
            redirect_nodes.add(requests[request]['faults'].items()[y][1]['redirect_node'])

        # [1] Primary Path rules
        primary_path = requests[request]['primary_path']
        for x in range(len(primary_path)):
            #print "Installing Primary Path rules in node", primary_path[x]
            # match(SRC_MAC, DEST_MAC, in_port, state=0, flags=PRIMARY_LINK_UP) -> action(output(next_primary_hop))

            if primary_path[x] not in detect_nodes and primary_path[x] not in redirect_nodes :
                #[NORMAL NODE]
                if x == 0: # first node in the primary path
                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(primary_path[x])]['h'+str(primary_path[x])],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        state=0)
                    flow_entry['actions']=[ofparser.OFPActionPushMpls()]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions']),ofparser.OFPInstructionGotoTable(1),ofparser.OFPInstructionWriteMetadata(16,0xffffffffffffffff)]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,primary_path[x],flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'primary')

                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(primary_path[x])]['h'+str(primary_path[x])],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        eth_type=0x8847,metadata=16)
                    flow_entry['actions']=[ofparser.OFPActionSetField(mpls_label=16),
                        ofparser.OFPActionOutput(mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x+1])],0)]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=1
                    flow_entries_dict = add_flow_entry(flow_entries_dict,primary_path[x],flow_entry)

                elif x == len(primary_path)-1: # last node in the primary path
                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x-1])],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        state=0,eth_type=0x8847)
                    flow_entry['actions']=[ofparser.OFPActionPopMpls(),
                        ofparser.OFPActionOutput(mn_topo_ports['s'+str(primary_path[x])]['h'+str(primary_path[x])],0)]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,primary_path[x],flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'primary')

                else: # intermediate node in the primary path
                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x-1])],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        state=0,eth_type=0x8847)
                    flow_entry['actions']=[ofparser.OFPActionOutput(mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x+1])],0)]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,primary_path[x],flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'primary')

            elif primary_path[x] in detect_nodes and primary_path[x] in redirect_nodes:
                #[DETECT AND REDIRECT]
                if x == 0: # first node in the primary path
                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(primary_path[x])]['h'+str(primary_path[x])],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        state=0)
                    flow_entry['actions']=[ofparser.OFPActionPushMpls(),ofparser.OFPActionGroup(group_ID[(request,(primary_path[x],primary_path[x+1]))])]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,primary_path[x],flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'primary')

                    #bucket creation (go to the next primary node)
                    max_len = 2000
                    actions = [ofparser.OFPActionOutput(mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x+1])],0),
                                ofparser.OFPActionSetField(mpls_label=16)]
                    weight = 0
                    watch_port = mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x+1])]
                    watch_group = ofproto.OFPG_ANY
                    bucket = ofparser.OFPBucket(weight, watch_port, watch_group,actions)
                    group_entries_dict = add_group_entry(group_entries_dict,primary_path[x],group_ID[(request,(primary_path[x],primary_path[x+1]))],bucket)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'group')
                else:
                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x-1])],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        state=0,eth_type=0x8847)
                    flow_entry['actions']=[ofparser.OFPActionGroup(group_ID[(request,(primary_path[x],primary_path[x+1]))])]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,primary_path[x],flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'primary')

                    #bucket creation (go to the next primary node)
                    max_len = 2000
                    actions = [ofparser.OFPActionOutput(mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x+1])],0)]
                    weight = 0
                    watch_port = mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x+1])]
                    watch_group = ofproto.OFPG_ANY
                    bucket = ofparser.OFPBucket(weight, watch_port, watch_group,actions)
                    group_entries_dict = add_group_entry(group_entries_dict,primary_path[x],group_ID[(request,(primary_path[x],primary_path[x+1]))],bucket)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'group')
            
            elif primary_path[x] in detect_nodes and primary_path[x] not in redirect_nodes:
                #[DETECT ONLY]
                '''
                se un edge node e' detect => non puo' non essere di redirect!
                '''
                #bucket creation (go to the next primary node)
                max_len = 2000
                actions = [ofparser.OFPActionOutput(mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x+1])],0)]
                weight = 0
                watch_port = mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x+1])]
                watch_group = ofproto.OFPG_ANY
                bucket = ofparser.OFPBucket(weight, watch_port, watch_group,actions)
                group_entries_dict = add_group_entry(group_entries_dict,primary_path[x],group_ID[(request,(primary_path[x],primary_path[x+1]))],bucket)
                flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'group')

                flow_entry = dict()
                flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x-1])],
                    eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),eth_type=0x8847, state=0)
                flow_entry['actions']=[ofparser.OFPActionGroup(group_ID[(request,(primary_path[x],primary_path[x+1]))])]
                flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                flow_entry['table_id']=0
                flow_entries_dict = add_flow_entry(flow_entries_dict,primary_path[x],flow_entry)
                flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'primary')
                '''
                nel nostro modello tutti i nodi di una request sono dei detect (tranne l'ultimo), quindi non puo' mai
                succedere che io sia solo request. l'unico modo sarebbe non gestire un fault di un certo link:
                in quel caso potrei essere un redirect puro...
                '''
            elif primary_path[x] not in detect_nodes and primary_path[x] in redirect_nodes:
                #REDIRECT ONLY
                flow_entry = dict()
                flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x-1])],
                    eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),eth_type=0x8847, state=0)
                flow_entry['actions']=[ofparser.OFPActionOutput(mn_topo_ports['s'+str(primary_path[x])]['s'+str(primary_path[x+1])],0)]
                flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                flow_entry['table_id']=0
                flow_entries_dict = add_flow_entry(flow_entries_dict,primary_path[x],flow_entry)
                flow_stats_dict = update_flow_stats(flow_stats_dict,primary_path[x],'primary')
        
        # for each fault of the current request
        for y in range(len(requests[request]['faults'].items())):
            
            fault = requests[request]['faults'].items()[y]
            #print "FAULT:", fault[0]
            tag = fault_ID[fault[0]]+16
            # MPLS label from 0 to 15 are reserved. Faults are numbered from 17. (tag=16 means NO FAULT)
            
            # [2] Detour Path rules
            # match(SRC_MAC, DST_MAC, in_port, TAG=ID_BROKEN_LINK) -> action(OUTPUT(NEXT_DETOUR_HOP))
            detour = requests[request]['faults'].items()[y][1]['detour_path']
            for z in range(1,len(detour)-1):
                #print "Installing Detour Node rules in node", detour[z]

                flow_entry = dict()
                flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(detour[z])]['s'+str(detour[z-1])],
                    eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                    eth_type=0x8847, mpls_label=tag)
                flow_entry['actions']=[ofparser.OFPActionOutput(mn_topo_ports['s'+str(detour[z])]['s'+str(detour[z+1])],0)]
                flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                flow_entry['table_id']=0
                flow_entries_dict = add_flow_entry(flow_entries_dict,detour[z],flow_entry)
                flow_stats_dict = update_flow_stats(flow_stats_dict,detour[z],'detour')

            #print "Installing Last Detour Node rules in node", detour[len(detour)-1]
            # match(SRC_MAC, DST_MAC, in_port, TAG=ID_BROKEN_LINK) -> action(OUTPUT(NEXT_PRIMARY_HOP), UNTAG)    

            # last detour node position in the primary path   
            l_d_n_index_in_p_p = primary_path.index(detour[len(detour)-1])
            
            flow_entry = dict()
            flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(detour[len(detour)-1])]['s'+str(detour[len(detour)-2])],
                    eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                    eth_type=0x8847, mpls_label=tag)
            if l_d_n_index_in_p_p == len(primary_path)-1: # l.d.n. is an edge switch
                flow_entry['actions']=[ofparser.OFPActionPopMpls(),
                    ofparser.OFPActionOutput(mn_topo_ports['s'+str(detour[len(detour)-1])]['h'+str(detour[len(detour)-1])],0)]
            else:
                flow_entry['actions']=[ofparser.OFPActionSetField(mpls_label=16),
                    ofparser.OFPActionOutput(mn_topo_ports['s'+str(detour[len(detour)-1])]['s'+str(primary_path[l_d_n_index_in_p_p + 1])],0)]
            flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
            flow_entry['table_id']=0
            flow_entries_dict = add_flow_entry(flow_entries_dict,detour[len(detour)-1],flow_entry)
            flow_stats_dict = update_flow_stats(flow_stats_dict,detour[len(detour)-1],'detour')

            # [3] Forward Back Path rules
            #match(SRC_MAC, DST_MAC, in_port, TAG=ID_BROKEN_LINK) -> action(OUTPUT(NEXT_FW_BACK_HOP))

            fw_back_path = requests[request]['faults'].items()[y][1]['fw_back_path']
            if fw_back_path != None:
                for z in range(1,len(fw_back_path)-1):
                    flow_entry = dict()
                    #print "Installing Forward back path rules in node", fw_back_path[z]
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(fw_back_path[z])]['s'+str(fw_back_path[z + 1])],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        eth_type=0x8847, mpls_label=tag)
                    flow_entry['actions']=[ofparser.OFPActionOutput(mn_topo_ports['s'+str(fw_back_path[z])]['s'+str(fw_back_path[z - 1])],0)]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,fw_back_path[z],flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,fw_back_path[z],'fw_back')

            # [4] Redirect node, Detect node and Detect&Redirect node rules
            redirect_node = requests[request]['faults'].items()[y][1]['redirect_node']
            detect_node = requests[request]['faults'].items()[y][1]['detect_node']

            # [4.1] Detect&Redirect node rules
            if redirect_node == detect_node:
                # match(SRC_MAC, DST_MAC, in_port, FLAG=LINK_DOWN) -> action(OUTPUT(DETOUR_PATH), TAG=ID_BROKEN_LINK)
                #print "Installing Detect & Redirect node rules in node", redirect_node
                # node position in the primary path   
                node_index_in_p_p = primary_path.index(redirect_node)

                if node_index_in_p_p == 0: # Detect&Redirect node is an edge switch
                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(redirect_node)]['h'+str(redirect_node)],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        state=tag)
                    flow_entry['actions']=[ofparser.OFPActionPushMpls()]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions']),
                        ofparser.OFPInstructionGotoTable(1),
                        ofparser.OFPInstructionWriteMetadata(tag,0xffffffffffffffff)]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,redirect_node,flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,redirect_node,'detect&red')

                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(redirect_node)]['h'+str(redirect_node)],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        eth_type=0x8847,metadata=tag)
                    flow_entry['actions']=[ofparser.OFPActionSetField(mpls_label=tag),
                        ofparser.OFPActionOutput(mn_topo_ports['s'+str(redirect_node)]['s'+str(detour[1])],0)]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=1
                    flow_entries_dict = add_flow_entry(flow_entries_dict,redirect_node,flow_entry)                

                else:
                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(redirect_node)]['s'+str(primary_path[node_index_in_p_p - 1])],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),eth_type=0x8847,
                        state=tag)
                    flow_entry['actions']=[ofparser.OFPActionSetField(mpls_label=tag),
                        ofparser.OFPActionOutput(mn_topo_ports['s'+str(redirect_node)]['s'+str(detour[1])],0)]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,redirect_node,flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,redirect_node,'detect&red')

                #bucket creation (set state and redirect on detour path)
                max_len = 2000
                actions = [osparser.OFPExpActionSetState(state=tag, table_id=0),ofparser.OFPActionSetField(mpls_label=tag),
                    ofparser.OFPActionOutput(mn_topo_ports['s'+str(redirect_node)]['s'+str(detour[1])],0)]
                weight = 0
                watch_port = mn_topo_ports['s'+str(redirect_node)]['s'+str(detour[1])]
                watch_group = ofproto.OFPG_ANY
                bucket = ofparser.OFPBucket(weight, watch_port, watch_group,actions)
                group_entries_dict = add_group_entry(group_entries_dict,primary_path[node_index_in_p_p],group_ID[(request,(primary_path[node_index_in_p_p],primary_path[node_index_in_p_p+1]))],bucket)
                
            else:
                # [4.2] Redirect only node rules
                #print "Installing Redirect only node rules in node", redirect_node
                node_index_in_p_p = primary_path.index(redirect_node)

                #match(SRC_MAC, DST_MAC, in_port, TAG=ID_BROKEN_LINK) -> action(SET_STATE(FAULT_x), OUTPUT(DETOUR_PATH))
                flow_entry = dict()
                flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(redirect_node)]['s'+str(primary_path[node_index_in_p_p+1])],
                        eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                        eth_type=0x8847, mpls_label=tag)
                flow_entry['actions']=[osparser.OFPExpActionSetState(state=tag, table_id=0),
                    ofparser.OFPActionOutput(mn_topo_ports['s'+str(redirect_node)]['s'+str(detour[1])],0)]
                flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                flow_entry['table_id']=0
                flow_entries_dict = add_flow_entry(flow_entries_dict,redirect_node,flow_entry)
                flow_stats_dict = update_flow_stats(flow_stats_dict,redirect_node,'redirect_only')
                
                #match(SRC_MAC, DST_MAC, in_port, STATE=FAULT_X) -> action(output(DETOUR_PATH), TAG=ID_BROKEN_LINK)
                flow_entry = dict()
                if node_index_in_p_p == 0: # Redirect only node is an edge switch
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(redirect_node)]['h'+str(redirect_node)],
                            eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                            state=tag)
                    flow_entry['actions']=[ofparser.OFPActionPushMpls()]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions']),
                        ofparser.OFPInstructionGotoTable(1),
                        ofparser.OFPInstructionWriteMetadata(tag,0xffffffffffffffff)]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,redirect_node,flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,redirect_node,'redirect_only')

                    flow_entry = dict()
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(redirect_node)]['h'+str(redirect_node)],
                            eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                            metadata=tag,eth_type=0x8847)
                    flow_entry['actions']=[ofparser.OFPActionSetField(mpls_label=tag),
                        ofparser.OFPActionOutput(mn_topo_ports['s'+str(redirect_node)]['s'+str(detour[1])],0)]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=1
                    flow_entries_dict = add_flow_entry(flow_entries_dict,redirect_node,flow_entry)
                else:
                    flow_entry['match']=ofparser.OFPMatch(in_port=mn_topo_ports['s'+str(redirect_node)]['s'+str(primary_path[node_index_in_p_p-1])],
                            eth_src=int_to_mac_str(request[0]),eth_dst=int_to_mac_str(request[1]),
                            eth_type=0x8847,state=tag)
                    flow_entry['actions']=[ofparser.OFPActionSetField(mpls_label=tag),
                        ofparser.OFPActionOutput(mn_topo_ports['s'+str(redirect_node)]['s'+str(detour[1])],0)]
                    flow_entry['inst']=[ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, flow_entry['actions'])]
                    flow_entry['table_id']=0
                    flow_entries_dict = add_flow_entry(flow_entries_dict,redirect_node,flow_entry)
                    flow_stats_dict = update_flow_stats(flow_stats_dict,redirect_node,'redirect_only')

                # [4.3] Detect only node rules
                #match(SRC_MAC, DST_MAC, in_port, FLAG=LINK_DOWN) -> action(TAG(ID_BROKEN_LINK), output(FWD_BACK_PATH))
                #print "Installing Detect only node rules in node", detect_node
                node_index_in_p_p = primary_path.index(detect_node)

                #bucket creation (set mpls tag and forward back)
                max_len = 2000
                actions=[ofparser.OFPActionSetField(mpls_label=tag),
                    ofparser.OFPActionOutput(ofproto.OFPP_IN_PORT,0)]
                weight = 0
                watch_port = mn_topo_ports['s'+str(primary_path[node_index_in_p_p])]['s'+str(primary_path[node_index_in_p_p-1])]
                watch_group = ofproto.OFPG_ANY
                bucket = ofparser.OFPBucket(weight, watch_port, watch_group,actions)
                group_entries_dict = add_group_entry(group_entries_dict,primary_path[node_index_in_p_p],group_ID[(request,(primary_path[node_index_in_p_p],primary_path[node_index_in_p_p+1]))],bucket)

    time.sleep(3)

    # We have to remove the hosts from the network to draw it, since we have created hosts on demand and we don't have positions
    e = range(len(pos.items())+1,len(G.nodes())+2)
    G.remove_nodes_from(e)
    nx.draw(G, pos, node_size=300, font_size=10, node_color='w', ax=None, with_labels=True)

    if not os.path.exists('./figs'):
        os.makedirs('./figs')

    if (os.path.isfile('./figs/network.png')):
        os.remove('./figs/network.png')
    plt.savefig("./figs/network.png", format="PNG")


def openXterm(hostname):
    global net
    makeTerm(net[hostname])

def pingAll():
    global net
    for src in net.hosts:
        for dst in net.hosts:
            if src != dst:
                #print(src.IP()+'# ping -i 1 '+dst.IP()+'&')
                src.cmd('ping -i 1 '+dst.IP()+'&')


def edgify(nodelist, unidirected=False):
    edges = [(nodelist[i], nodelist[i + 1]) for i in range(len(nodelist) - 1)]
    if unidirected:
        uedges = []
        for e in edges:
            if e[0] > e[1]:
                uedges.append((e[1], e[0]))
            else:
                uedges.append(e)
        return uedges
    else:
        return edges


def get_bck_path(pp, dp):
    path = []
    idx_in = pp.index(dp[0])
    idx_out = pp.index(dp[-1])
    path.extend(pp[0:idx_in])
    path.extend(dp)
    path.extend(pp[idx_out+1:])
    return path


def draw_used_capacity(fault_edge=None, no_fault=False):

    if fault_edge == None and no_fault==False:
        for e in G.edges():
            draw_used_capacity(e)
        draw_used_capacity(None, True)

    max_width = 20
    plt.clf()
    nx.draw(G, pos, node_size=300, font_size=10, node_color='w', with_labels=True, alpha=1, style='dotted')

    c = Counter()
    r_count = 0;
    for r in requests:
        areq = requests[r]
        pp = areq['primary_path']
        if fault_edge == None or fault_edge not in areq['faults']:
            path = pp
            #print r, 'pp', path
        else:
            dp = areq['faults'][fault_edge]['detour_path']
            path = get_bck_path(pp, dp)
            #print r, 'pp', pp, 'bck', path

        edges = edgify(path, True)
        if fault_edge in edges:
            print "ALERT fault_edge in bck path!", r, 'path', path
        c.update(edges)

    m = c.most_common(1)

    for e in c:
        width = (float(c[e]) / m[0][1]) * max_width
        if(width<1):
            width = 1
        #print e, width
        nx.draw_networkx_edges(G, pos,
                       edgelist=[e],
                       width=width, color='g')

    if fault_edge is not None:
        nx.draw_networkx_edges(G, pos,
            edgelist=[fault_edge],
            width=4, edge_color='r', alpha=0.5)
        print "drawing used capacity with fault", fault_edge
        s = './figs/capacity-f-'+str(fault_edge[0])+'-'+str(fault_edge[1])+'.png'
    else:
        print "drawing used capacity"
        s = './figs/capacity-no-fault.png'
    
    plt.savefig(s, format="PNG")
    #plt.show()
    plt.clf()


def draw_edge_node(nodes, alpha, color, style='solid'):
    nx.draw_networkx_nodes(G, pos,
                           nodelist=nodes,
                           node_color=color,
                           node_size=300,
                           font_size=10,
                           alpha=alpha)
    edges = [(nodes[i], nodes[i + 1]) for i in range(len(nodes) - 1)]
    nx.draw_networkx_edges(G, pos,
                           edgelist=edges,
                           width=4, alpha=alpha,
                           edge_color=color, style=style)


def draw_fault_scenario(title, fault_edge, pp, dp, fwp):
    nx.draw(G, pos, node_size=300, font_size=10, node_color='w', alpha=1, with_labels=True)

    if title is not None:
        plt.text(0.5, 0.5, title, fontsize=12)

    if pp is not None:
        draw_edge_node(pp, 0.8, 'b')
        # Source
        nx.draw_networkx_nodes(G, pos,
                               nodelist=[pp[0]],
                               node_color='black',
                               node_size=500,
                               label='S',
                               font_size=10,
                               node_shape='s',
                               alpha=0.5)
    # Detour path
    if dp is not None:
        draw_edge_node(dp, 0.8, 'g')

    # Fault edge
    if fault_edge is not None:
        nx.draw_networkx_edges(G, pos,
                               edgelist=[fault_edge],
                               width=4, alpha=0.8,
                               edge_color='r')
    # FW Back path
    if fwp is not None:
        draw_edge_node(fwp, 0.8, 'y', 'dashed')


def draw_detour_paths(pp_edge=None, show=False):

    if pp_edge == None:
        for aedge in requests:
            draw_detour_paths(aedge, show)
        return

    areq = requests[pp_edge]

    s = 'r-' + str(pp_edge[0]) + '-' + str(pp_edge[1] + 'all-faults')

    nx.draw(G, pos, node_size=300, font_size=10, node_color='w', alpha=1, with_labels=True)

    pp = areq['primary_path']
    draw_edge_node(pp, 0.8, 'b')

    nx.draw_networkx_nodes(G, pos,
                       nodelist=[pp[0]],
                       node_color='black',
                       node_size=500,
                       label='S',
                       font_size=10,
                       node_shape='s',
                       alpha=0.5)

    f_count = len(areq['faults'])

    for f_edge in areq['faults']:
        fault = areq['faults'][f_edge]
        dp = fault['detour_path']

        draw_edge_node(dp, 0.4, 'g')

    print "Drawing detour paths for request", pp_edge

    if show:
        plt.show()
    else:
        plt.savefig('./figs/' + s + '.png', format="PNG")
    plt.clf()


def draw_requests(pp_edge=None, show=False):

    if pp_edge == None:
        for aedge in requests:
            draw_requests(aedge, show)
        return

    areq = requests[pp_edge]

    s = 'r-' + str(pp_edge[0]) + '-' + str(pp_edge[1])
    draw_fault_scenario(title=s, pp=areq['primary_path'], dp=None, fwp=None, fault_edge=None)

    print "Drawing request", pp_edge

    if show:
        plt.show()
    else:
        plt.savefig('./figs/' + s + '.png', format="PNG")
    plt.clf()

    for f_edge in areq['faults']:
        fault = areq['faults'][f_edge]

        s = 'r-' + str(pp_edge[0]) + '-' + str(pp_edge[1]) + '-f-' + str(
            f_edge[0]) + '-' + str(f_edge[1])

        draw_fault_scenario(title=s, pp=areq['primary_path'], dp=fault[
                            'detour_path'], fwp=fault['fw_back_path'], fault_edge=f_edge)

        print "Drawing request", pp_edge, "with fault", f_edge

        if show:
            plt.show()
        else:
            plt.savefig('./figs/' + s + '.png', format="PNG")
        plt.clf()


def draw_faults(fault_edge=None, show=False):

    if fault_edge == None:
        for aedge in faults:
            draw_faults(aedge, show)
        return

    afault = faults[fault_edge]

    for pp_edge in afault['requests']:
        areq = afault['requests'][pp_edge]

        s = 'f-' + str(fault_edge[0]) + '-' + str(fault_edge[1]) + '-r-' + str(pp_edge[0]) + '-' + str(pp_edge[1])

        draw_fault_scenario(title=s, pp=areq['primary_path'], dp=areq[
                'detour_path'], fwp=areq['fw_back_path'], fault_edge=fault_edge)

        print "Drawing fault", fault_edge, "with request", pp_edge

        if show:
            plt.show()
        else:
            plt.savefig('./figs/' + s + '.png', format="PNG")
        plt.clf()


def draw_backup_paths(fault_edge=None, show=False):

    if fault_edge == None:
        for aedge in faults:
            draw_backup_paths(aedge, show)
        return

    nx.draw(G, pos, node_size=300, font_size=10, node_color='w', alpha=1, with_labels=True)

    nx.draw_networkx_edges(G, pos,
                               edgelist=[fault_edge],
                               width=4, alpha=0.8,
                               edge_color='r')

    afault = faults[fault_edge]

    for pp_edge in afault['requests']:
        areq = afault['requests'][pp_edge]

        s = 'f-' + str(fault_edge[0]) + '-' + str(fault_edge[1]) + '-all-bck-paths'

        pp=areq['primary_path']
        dp=areq['detour_path']

        p0 = pp.index(fault_edge[0])
        p1 = pp.index(fault_edge[1])

        if p0 < p1:
            color = 'b'
        else:
            color = 'y'

        bck_path = get_bck_path(pp=pp, dp=dp)

        draw_edge_node(nodes=bck_path, alpha=0.3, color=color)

    print "Drawing backup paths for fault", fault_edge

    if show:
        plt.show()
    else:
        plt.savefig('./figs/' + s + '.png', format="PNG")
    plt.clf()


def draw_all():
    draw_used_capacity()
    draw_requests()
    draw_faults()
    draw_detour_paths()

# returns "xx:xx:xx:xx:xx:xx"
def int_to_mac_str(host_number):
    mac_str = "{0:0{1}x}".format(int(host_number),12) # converts to hex with zero pad to 48bit
    return ':'.join(mac_str[i:i+2] for i in range(0, len(mac_str), 2)) # adds ':'

# returns "10.x.x.x"
def int_to_ip_str(host_number):
    ip = (10<<24) + int(host_number)
    return ".".join(map(lambda n: str(ip>>n & 0xFF), [24,16,8,0]))