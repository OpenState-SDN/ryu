'''
STATEFUL TABLE 0

Lookup-scope=IPV4_DST,IPV4_SRC,TCP_DST,TCP_SRC
Update-scope=IPV4_DST,IPV4_SRC,TCP_DST,TCP_SRC

     _______ 
    |       |--h2
h1--|   S1  |--h3
    |_______|--h4

h1 is the client 10.0.0.1
h1 connects to an EchoServer 10.0.0.2:80
h2, h3, h4 are 3 replicas of the server:
h2 is listening at 10.0.0.2:200 
h3 is listening at 10.0.0.3:300
h4 is listening at 10.0.0.4:400

$ ryu-manager ryu/ryu/app/openstate/forwarding_consistency_1_to_many.py
$ sudo mn --topo single,4 --switch user --mac --controller remote
mininet> xterm h1 h1 h1 h2 h3 h4
h2# python ryu/ryu/app/openstate/echo_server.py 200
h3# python ryu/ryu/app/openstate/echo_server.py 300
h4# python ryu/ryu/app/openstate/echo_server.py 400

Let's try to connect from h1 to the EchoServer and send some message:
h1# nc 10.0.0.2 80
If we keep the connection open, the responding EchoServer is always the same.
If we open another connection (from the 2nd terminal of h1) maybe we get connected to another replica.
If we close it and re-connect, maybe we are connected to another replica.
'''

import logging
import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osp
import ryu.ofproto.openstate_v1_0_parser as osparser

LOG = logging.getLogger('app.openstate.forwarding_consistency_1_to_many')

SWITCH_PORTS = 4
LOG.info("OpenState Forwarding Consistency sample app initialized")
LOG.info("Supporting MAX %d ports per switch" % SWITCH_PORTS)

class OSLoadBalancing(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        
        super(OSLoadBalancing, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath

        LOG.info("Configuring switch %d..." % datapath.id)

        """ Set table 0 as stateful """
        req = osparser.OFPExpMsgConfigureStatefulTable(datapath=datapath, 
                                                    table_id=0, 
                                                    stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {ip_src, ip_dst, tcp_src, tcp_dst} """
        req = osparser.OFPExpMsgKeyExtract(datapath=datapath, 
                                                command=osp.OFPSC_EXP_SET_L_EXTRACTOR, 
                                                fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST], 
                                                table_id=0)
        datapath.send_msg(req)

        """ Set update extractor = {ip_src, ip_dst, tcp_src, tcp_dst} (same as lookup) """
        req = osparser.OFPExpMsgKeyExtract(datapath=datapath, 
                                                command=osp.OFPSC_EXP_SET_U_EXTRACTOR, 
                                                fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST], 
                                                table_id=0)
        datapath.send_msg(req)

        """ Group table setup """
        buckets = []
        # Action Bucket: <PWD port_i , SetState(i-1)
        for port in range(2,SWITCH_PORTS+1):
            max_len = 2000
            dest_ip=self.int_to_ip_str(port)
            dest_eth=self.int_to_mac_str(port)
            dest_tcp=(port)*100
            actions = [ osparser.OFPExpActionSetState(state=port, table_id=0),
                        ofparser.OFPActionSetField(ipv4_dst=dest_ip),
                        ofparser.OFPActionSetField(eth_dst=dest_eth),
                        ofparser.OFPActionSetField(tcp_dst=dest_tcp),
                        ofparser.OFPActionOutput(port=port, max_len=max_len) ]

            buckets.append(ofparser.OFPBucket(weight=100, 
                                                watch_port=ofp.OFPP_ANY, 
                                                watch_group=ofp.OFPG_ANY,
                                                actions=actions))

        req = ofparser.OFPGroupMod(datapath=datapath, 
                                     command=ofp.OFPGC_ADD,
                                     type_=ofp.OFPGT_SELECT, 
                                     group_id=1, 
                                     buckets=buckets)
        datapath.send_msg(req)
        

        
        """ ARP packets flooding """
        match = ofparser.OFPMatch(eth_type=0x0806)
        actions = [ofparser.OFPActionOutput(port=ofp.OFPP_FLOOD)]
        self.add_flow(datapath=datapath, table_id=0, priority=100,
                        match=match, actions=actions)

        """ Reverse path flow """
        for in_port in range(2, SWITCH_PORTS + 1):
            src_ip=self.int_to_ip_str(in_port)
            src_eth=self.int_to_mac_str(in_port)
            src_tcp=in_port*100
            # we need to match an IPv4 (0x800) TCP (6) packet to do SetField()
            match = ofparser.OFPMatch(in_port=in_port, eth_type=0x800, ip_proto=6, ipv4_src=src_ip,eth_src=src_eth,tcp_src=src_tcp)
            actions = [ofparser.OFPActionSetField(ipv4_src="10.0.0.2"),
                       ofparser.OFPActionSetField(eth_src="00:00:00:00:00:02"),
                       ofparser.OFPActionSetField(tcp_src=80),
                       ofparser.OFPActionOutput(port=1, max_len=0)]                   
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                    match=match, actions=actions)

        """ Forwarding consistency rules"""
        match = ofparser.OFPMatch(in_port=1, state=0, eth_type=0x800, ip_proto=6)
        actions = [ofparser.OFPActionGroup(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=100,
                match=match, actions=actions)

        for state in range(2,SWITCH_PORTS+1):
            dest_ip=self.int_to_ip_str(state)
            dest_eth=self.int_to_mac_str(state)
            dest_tcp=(state)*100
            match = ofparser.OFPMatch(in_port=1, state=state, eth_type=0x800, ip_proto=6)
            actions = [ ofparser.OFPActionSetField(ipv4_dst=dest_ip),
                        ofparser.OFPActionSetField(eth_dst=dest_eth),
                        ofparser.OFPActionSetField(tcp_dst=dest_tcp),
                        ofparser.OFPActionOutput(port=state, max_len=0)]        
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                    match=match, actions=actions)
        
    def add_flow(self, datapath, table_id, priority, match, actions):
        inst = [ofparser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    # returns "xx:xx:xx:xx:xx:xx"
    def int_to_mac_str(self, host_number):
        mac_str = "{0:0{1}x}".format(int(host_number),12) # converts to hex with zero pad to 48bit
        return ':'.join(mac_str[i:i+2] for i in range(0, len(mac_str), 2)) # adds ':'

    # returns "10.x.x.x"
    def int_to_ip_str(self, host_number):
        ip = (10<<24) + int(host_number)
        return ".".join(map(lambda n: str(ip>>n & 0xFF), [24,16,8,0]))