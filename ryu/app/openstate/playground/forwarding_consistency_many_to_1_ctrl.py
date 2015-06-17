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

LOG = logging.getLogger('app.openstate.forwarding_consistency_many_to_1_ctrl')

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
        actions = []
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
            
                if datapath.id==5:
                    out_port = 4
                    self.add_flow_many_to_1(datapath, in_port, out_port, ip_src, ip_dst, tcp_src, tcp_dst)
                    actions = [ofparser.OFPActionOutput(out_port, 0)]
            
                if msg.buffer_id == ofp.OFP_NO_BUFFER:
                        data = msg.data
                    
                out = ofparser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        options ={1: self.one_to_many_switch,
                  2: self.middleswitch,
                  3: self.middleswitch,
                  4: self.middleswitch,
                  5: self.many_to_one_switch
        }

        options[datapath.id](datapath)

    def one_to_many_switch(self, datapath):
        self.send_features_request(datapath)
        self.send_group_mod(datapath)
        self.send_table_mod(datapath)

        self.send_key_lookup_1(datapath)
        self.send_key_update_1(datapath)

        self.add_flow_1_to_many(datapath)
        
    def middleswitch(self, datapath):
        self.send_features_request(datapath)
        self.add_middleswitch_default(datapath)

    def many_to_one_switch(self, datapath):
        self.send_features_request(datapath)
        self.add_flow_default_many_to_1(datapath)

    def add_flow_1_to_many(self, datapath, table_miss=False):
        LOG.info("Configuring flow table for switch %d" % datapath.id)     

        if table_miss:
            LOG.debug("Installing table miss...")
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

        else:

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

            
            # Reverse path flow
            for in_port in range(2, SWITCH_PORTS + 1):
                match = ofparser.OFPMatch(in_port=in_port)
                actions = [
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

            # the state of a flow is the selected output port for that flow
            for state in range(SWITCH_PORTS):
                if state == 0:
                    # if state=DEFAULT => send it to the first group entry in the group table
                    actions = [
                            ofparser.OFPActionGroup(1)]
                    match = ofparser.OFPMatch(
                            in_port=1, state=state, eth_type=0x800)
                else:
                    # state x means output port x+1
                    actions = [
                        osparser.OFPExpActionSetState(state=state, table_id=0),
                        ofparser.OFPActionOutput(state+1, 0)]
                    match = ofparser.OFPMatch(
                        in_port=1, state=state, eth_type=0x800)
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


    def add_flow_many_to_1(self, datapath, in_port, out_port, ip_src, ip_dst, tcp_src, tcp_dst):        
        self.counter+=1
        #LOG.info('Installing new forward rule for switch %d (rule # %d)' % (datapath.id, self.counter)) 
        
        # reverse path rule
        actions = [ofparser.OFPActionOutput(in_port, 0)]
        match = ofparser.OFPMatch(
            in_port=out_port, eth_type=0x800, ip_proto=6, ipv4_src=ip_dst, ipv4_dst=ip_src, tcp_src=tcp_dst, tcp_dst=tcp_src)
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

        # forward path rule
        actions = [ofparser.OFPActionOutput(out_port, 0)]
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

    def add_flow_default_many_to_1(self, datapath):
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

    def add_middleswitch_default(self, datapath):
        LOG.info("Configuring default flow entries for switch %d" % datapath.id)       
        
        match = ofparser.OFPMatch(in_port=1)
        actions = [
            ofparser.OFPActionOutput(2,0)]
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

        match = ofparser.OFPMatch(in_port=2)
        actions = [
            ofparser.OFPActionOutput(1,0)]
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

    def send_features_request(self, datapath):
        req = ofparser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def ip_addr_ntoa(self,ip):
        return socket.inet_ntoa(addrconv.ipv4.text_to_bin(ip))

    def send_key_lookup_1(self, datapath):
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)

    def send_key_update_1(self, datapath):
        key_update_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST], table_id=0)
        datapath.send_msg(key_update_extractor)

    def send_group_mod(self, datapath):
        buckets = []
        # Action Bucket: <PWD port_i , SetState(i-1)
        for port in range(2,SWITCH_PORTS+1):
            max_len = 2000
            actions = [
                osparser.OFPExpActionSetState(state=port-1, table_id=0),
                ofparser.OFPActionOutput(port, max_len)]

            weight = 100
            watch_port = ofp.OFPP_ANY
            watch_group = ofp.OFPG_ANY
            buckets.append(ofparser.OFPBucket(weight, watch_port, watch_group,actions))

        group_id = 1
        req = ofparser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                     ofp.OFPGT_SELECT, group_id, buckets)
        datapath.send_msg(req)

    def send_table_mod(self, datapath):
        req = osparser.OFPExpMsgConfigureStatefulTable(datapath=datapath, table_id=0, stateful=1)
        datapath.send_msg(req)
    
