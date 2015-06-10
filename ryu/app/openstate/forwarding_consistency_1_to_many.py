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

$ ryu-manager ryu.b/ryu/app/openstate/forwarding_consistency_1_to_many.py
$ sudo mn --topo single,4 --switch user --mac --controller remote
mininet> xterm h1 h1 h1 h2 h3 h4
h2# python ryu.b/ryu/app/openstate/echo_server.py 200
h3# python ryu.b/ryu/app/openstate/echo_server.py 300
h4# python ryu.b/ryu/app/openstate/echo_server.py 400

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
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        LOG.info("Configuring switch %d..." % datapath.id)

        """ Set table 0 as stateful """
        req = parser.OFPExpMsgConfigureStatefulTable(datapath=datapath, 
                                                    table_id=0, 
                                                    stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {ip_src, ip_dst, tcp_src, tcp_dst} """
        req = parser.OFPExpMsgKeyExtract(datapath=datapath, 
                                                command=ofp.OFPSC_EXP_SET_L_EXTRACTOR, 
                                                fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST], 
                                                table_id=0)
        datapath.send_msg(req)

        """ Set update extractor = {ip_src, ip_dst, tcp_src, tcp_dst} (same as lookup) """
        req = parser.OFPExpMsgKeyExtract(datapath=datapath, 
                                                command=ofp.OFPSC_EXP_SET_U_EXTRACTOR, 
                                                fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST], 
                                                table_id=0)
        datapath.send_msg(req)

        """ Group table setup """
        buckets = []
        # Action Bucket: <PWD port_i , SetState(i-1)
        for port in range(2,SWITCH_PORTS+1):
            max_len = 2000
            dest_ip="10.0.0."+str(port)
            dest_eth="00:00:00:00:00:0"+str(port)
            dest_tcp=(port)*100
            actions = [ parser.OFPExpActionSetState(state=port, table_id=0),
                        parser.OFPActionSetField(ipv4_dst=dest_ip),
                        parser.OFPActionSetField(eth_dst=dest_eth),
                        parser.OFPActionSetField(tcp_dst=dest_tcp),
                        parser.OFPActionOutput(port=port, max_len=max_len) ]

            buckets.append(parser.OFPBucket(weight=0, 
                                                watch_port=ofp.OFPP_ANY, 
                                                watch_group=ofp.OFPG_ANY,
                                                actions=actions))

        req = parser.OFPGroupMod(datapath=datapath, 
                                     command=ofp.OFPGC_ADD,
                                     type_=ofp.OFPGT_RANDOM, 
                                     group_id=1, 
                                     buckets=buckets)
        datapath.send_msg(req)
        

        
        """ ARP packets flooding """
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(port=ofp.OFPP_FLOOD)]
        self.add_flow(datapath=datapath, table_id=0, priority=100,
                        match=match, actions=actions)

        """ Reverse path flow """
        for in_port in range(2, SWITCH_PORTS + 1):
            src_ip="10.0.0."+str(in_port)
            src_eth="00:00:00:00:00:0"+str(in_port)
            src_tcp=in_port*100
            # we need to match an IPv4 (0x800) TCP (6) packet to do SetField()
            match = parser.OFPMatch(in_port=in_port, eth_type=0x800, ip_proto=6, ipv4_src=src_ip,eth_src=src_eth,tcp_src=src_tcp)
            actions = [parser.OFPActionSetField(ipv4_src="10.0.0.2"),
                       parser.OFPActionSetField(eth_src="00:00:00:00:00:02"),
                       parser.OFPActionSetField(tcp_src=80),
                       parser.OFPActionOutput(port=1, max_len=0)]                   
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                    match=match, actions=actions)

        """ Forwarding consistency rules"""
        match = parser.OFPMatch(in_port=1, state=0, eth_type=0x800, ip_proto=6)
        actions = [parser.OFPActionGroup(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=100,
                match=match, actions=actions)

        for state in range(2,SWITCH_PORTS+1):
            dest_ip="10.0.0."+str(state)
            dest_eth="00:00:00:00:00:0"+str(state)
            dest_tcp=(state)*100
            match = parser.OFPMatch(in_port=1, state=state, eth_type=0x800, ip_proto=6)
            actions = [ parser.OFPExpActionSetState(state=state, table_id=0),
                        parser.OFPActionSetField(ipv4_dst=dest_ip),
                        parser.OFPActionSetField(eth_dst=dest_eth),
                        parser.OFPActionSetField(tcp_dst=dest_tcp),
                        parser.OFPActionOutput(port=state, max_len=0)]        
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                    match=match, actions=actions)
        
    def add_flow(self, datapath, table_id, priority, match, actions):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

