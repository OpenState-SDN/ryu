#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import struct
import socket
import random

from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib import addrconv
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, \
    HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osp
import ryu.ofproto.openstate_v1_0_parser as osparser
from ryu.lib.packet import packet
from ryu.topology import event

LOG = logging.getLogger('app.openstate.forwarding_consistency_1_to_many_ctrl_os_of')

SWITCH_PORTS = 4
IPV4 = ipv4.ipv4.__name__
TCP = tcp.tcp.__name__

class OSLoadBalancing(app_manager.RyuApp):
    OFP_VERSIONS = [ofp.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        LOG.info("OpenState Forwarding Consistency sample app initialized")
        LOG.info("Supporting MAX %d ports per switch" % SWITCH_PORTS)
        super(OSLoadBalancing, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.counter = 0

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        in_port = msg.match['in_port']
        ip_dst = None
        ip_src = None
        tcp_dst = None
        tcp_src = None
        data = None

        pkt = packet.Packet(msg.data)
        
        header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols if type(p) != str)

        out_port = random.randint(2,SWITCH_PORTS)

        if IPV4 in header_list:
            ip_dst = self.ip_addr_ntoa(header_list[IPV4].dst)
            ip_src = self.ip_addr_ntoa(header_list[IPV4].src)
            
            if TCP in header_list:
                tcp_src = header_list[TCP].src_port
                tcp_dst = header_list[TCP].dst_port
            
                self.add_flow(datapath, in_port, out_port, ip_src, ip_dst, tcp_src, tcp_dst)

                dest_ip="10.0.0."+str(out_port)
                dest_eth="00:00:00:00:00:0"+str(out_port)
                dest_tcp=out_port*100
                actions = [
                    ofparser.OFPActionSetField(ipv4_dst=dest_ip),
                    ofparser.OFPActionSetField(eth_dst=dest_eth),
                    ofparser.OFPActionSetField(tcp_dst=dest_tcp),
                    ofparser.OFPActionOutput(out_port, 0)]
                
                if msg.buffer_id == ofp.OFP_NO_BUFFER:
                    data = msg.data
                
                out = ofparser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                 

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        self.send_features_request(datapath)

        self.send_table_mod(datapath)

        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        # install table miss - ARP - reverse path rules
        self.add_flow_default(datapath)

        
    def add_flow_default(self, datapath):
        LOG.info("Configuring default flow entries for switch %d" % datapath.id)     

        #table miss
        actions = [ofparser.OFPActionOutput(
            ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        match = ofparser.OFPMatch()
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)

        datapath.send_msg(mod)

        # Reverse path flow
        for in_port in range(2, SWITCH_PORTS + 1):
            src_ip="10.0.0."+str(in_port)
            src_eth="00:00:00:00:00:0"+str(in_port)
            src_tcp=in_port*100
            # we need to match an IPv4 (0x800) TCP (6) packet to do SetField()
            match = ofparser.OFPMatch(in_port=in_port, eth_type=0x800, ip_proto=6, ipv4_src=src_ip,eth_src=src_eth,tcp_src=src_tcp)
            actions = [ofparser.OFPActionSetField(ipv4_src="10.0.0.2"),
                ofparser.OFPActionSetField(eth_src="00:00:00:00:00:02"),
                ofparser.OFPActionSetField(tcp_src=80),
                ofparser.OFPActionOutput(1,0)]
            inst = [ofparser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod = ofparser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=32767, buffer_id=ofp.OFP_NO_BUFFER,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                flags=0, match=match, instructions=inst)
            datapath.send_msg(mod)

        # ARP packets flooding
        match = ofparser.OFPMatch(eth_type=0x0806)
        actions = [
            ofparser.OFPActionOutput(ofp.OFPP_FLOOD)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    
    def add_flow(self, datapath, in_port, out_port, ip_src, ip_dst, tcp_src, tcp_dst):        
        self.counter+=1
        LOG.info('Installing new forward rule for switch %d (rule # %d)' % (datapath.id, self.counter)) 
        dest_ip="10.0.0."+str(out_port)
        dest_eth="00:00:00:00:00:0"+str(out_port)
        dest_tcp=out_port*100
        actions = [
            ofparser.OFPActionSetField(ipv4_dst=dest_ip),
            ofparser.OFPActionSetField(eth_dst=dest_eth),
            ofparser.OFPActionSetField(tcp_dst=dest_tcp),
            ofparser.OFPActionOutput(out_port, 0)]
        match = ofparser.OFPMatch(
            in_port=in_port, eth_type=0x800, ip_proto=6, ipv4_src=ip_src, ipv4_dst=ip_dst, tcp_src=tcp_src, tcp_dst=tcp_dst)
        inst = [
            ofparser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0,
            hard_timeout=0, priority=32767,
            buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    
    def send_table_mod(self, datapath):
        req = osparser.OFPExpMsgConfigureStatefulTable(datapath=datapath, table_id=0, stateful=1)
        datapath.send_msg(req)
    
    def send_features_request(self, datapath):
        req = ofparser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def send_key_lookup(self, datapath):
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        key_update_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST], table_id=0)
        datapath.send_msg(key_update_extractor)

    def ip_addr_ntoa(self,ip):
        return socket.inet_ntoa(addrconv.ipv4.text_to_bin(ip))



