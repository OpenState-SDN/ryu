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
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.topology import event



LOG = logging.getLogger('app.openstate.forwarding_consistency_many_to_many_ctrl')

SWITCH_PORTS = 4
IPV4 = ipv4.ipv4.__name__
TCP = tcp.tcp.__name__

class OSLoadBalancing(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

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
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        ip_dst = None
        ip_src = None
        tcp_dst = None
        tcp_src = None
        data = None

        pkt = packet.Packet(msg.data)
        
        header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols if type(p) != str)

        out_port= random.randint(2,SWITCH_PORTS)
        out_port_m_to_m = random.randint(4,6)

        if IPV4 in header_list:
            ip_dst = self.ip_addr_ntoa(header_list[IPV4].dst)
            ip_src = self.ip_addr_ntoa(header_list[IPV4].src)
            
            if TCP in header_list:
                tcp_src = header_list[TCP].src_port
                tcp_dst = header_list[TCP].dst_port
            
                if datapath.id==1:
                    self.add_flow_1_to_many(datapath, in_port, out_port, ip_src, ip_dst, tcp_src, tcp_dst)
                    actions = [parser.OFPActionOutput(out_port, 0)]

                elif datapath.id==4:
                    #the rule entries are the same as many to 1 case
                    self.add_flow_many_to_1(datapath, in_port, out_port_m_to_m, ip_src, ip_dst, tcp_src, tcp_dst)
                    actions = [parser.OFPActionOutput(out_port_m_to_m, 0)]
               
                elif datapath.id==7:
                    out_port = 4
                    self.add_flow_many_to_1(datapath, in_port, out_port, ip_src, ip_dst, tcp_src, tcp_dst)
                    actions = [parser.OFPActionOutput(out_port, 0)]
            
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        options ={1: self.one_to_many_switch,
                  2: self.middleswitch,
                  3: self.middleswitch,
                  4: self.many_to_many_switch,
                  5: self.middleswitch,
                  6: self.middleswitch,
                  7: self.many_to_one_switch
        }


        options[datapath.id](datapath)

    def one_to_many_switch(self, datapath):
        self.send_features_request(datapath)
        self.add_flow_default_1_to_many(datapath)
        
    def middleswitch(self, datapath):
        self.send_features_request(datapath)
        self.add_middleswitch_default(datapath)

    def many_to_many_switch(self, datapath):
        self.send_features_request(datapath)
        #we use the same default many to one rules
        self.add_flow_default_many_to_1(datapath)

    def many_to_one_switch(self, datapath):
        self.send_features_request(datapath)
        self.add_flow_default_many_to_1(datapath)

    def add_flow_default_1_to_many(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        LOG.info("Configuring default flow entries for switch %d" % datapath.id)      

        #table miss
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)

        datapath.send_msg(mod)

        # Reverse path flow
        for in_port in range(2, SWITCH_PORTS + 1):
            # we need to match an IPv4 (0x800) TCP (6) packet to do SetField()
            match = parser.OFPMatch(in_port=in_port, eth_type=0x800)
            actions = [parser.OFPActionOutput(1,0)]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=32767, buffer_id=ofproto.OFP_NO_BUFFER,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                flags=0, match=match, instructions=inst)
            datapath.send_msg(mod)

        # ARP packets flooding
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow_1_to_many(self, datapath, in_port, out_port, ip_src, ip_dst, tcp_src, tcp_dst):        

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.counter+=1
        LOG.info('Installing new forward rule for switch %d (rule # %d)' % (datapath.id, self.counter)) 
        actions = [parser.OFPActionOutput(out_port, 0)]
        match = parser.OFPMatch(
            in_port=in_port, eth_type=0x800, ip_proto=6, ipv4_src=ip_src, ipv4_dst=ip_dst, tcp_src=tcp_src, tcp_dst=tcp_dst)
        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0,
            hard_timeout=0, priority=32767,
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)


    def add_flow_many_to_1(self, datapath, in_port, out_port, ip_src, ip_dst, tcp_src, tcp_dst):        

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.counter+=1
        LOG.info('Installing new forward rule for switch %d (rule # %d)' % (datapath.id, self.counter)) 
        
        # reverse path rule
        actions = [parser.OFPActionOutput(in_port, 0)]
        match = parser.OFPMatch(
            in_port=out_port, eth_type=0x800, ip_proto=6, ipv4_src=ip_dst, ipv4_dst=ip_src, tcp_src=tcp_dst, tcp_dst=tcp_src)
        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0,
            hard_timeout=0, priority=32767,
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        # forward path rule
        actions = [parser.OFPActionOutput(out_port, 0)]
        match = parser.OFPMatch(
            in_port=in_port, eth_type=0x800, ip_proto=6, ipv4_src=ip_src, ipv4_dst=ip_dst, tcp_src=tcp_src, tcp_dst=tcp_dst)
        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0,
            hard_timeout=0, priority=32767,
            buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow_default_many_to_1(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        LOG.info("Configuring default flow entries for switch %d" % datapath.id)     

        #table miss
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)

        datapath.send_msg(mod)

        # ARP packets flooding
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)


    def add_middleswitch_default(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        LOG.info("Configuring default flow entries for switch %d" % datapath.id)       
        
        match = parser.OFPMatch(in_port=1)
        actions = [
            parser.OFPActionOutput(2,0)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(in_port=2)
        actions = [
            parser.OFPActionOutput(1,0)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)     

    def send_features_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def ip_addr_ntoa(self,ip):
        return socket.inet_ntoa(addrconv.ipv4.text_to_bin(ip))
    