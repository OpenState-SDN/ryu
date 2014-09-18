
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.topology import event
import time

'''
Applicazione di test che fa uso di Global States (flags), Flow States e Metadata contemporaneamente e dei comandi OFPSC_ADD_FLOW_STATE e OFPSC_DEL_FLOW_STATE

Ci sono 4 host:
h1 e h2 si pingano sempre
h3 e h4 si pingano per 5 secondi, poi non riescono per altri 5 e infine riescono sempre

TABLE 0 (stateless)

ipv4_src=10.0.0.1, in_port=1    --->    SetState(state=0xfffffffa,stage_id=1), SetFlag("1*01********"), WriteMetadata(64954), GotoTable(1)
ipv4_src=10.0.0.2, in_port=2    --->    forward(1)
ipv4_src=10.0.0.3, in_port=3    --->    GotoTable(1)
ipv4_src=10.0.0.4, in_port=4    --->    forward(3)

TABLE 1 (stateful) Lookup-scope=Update-scope=OXM_OF_IPV4_SRC)

ipv4_src=10.0.0.1, metadata=64954, flags="1*01********", state=0xfffffffa   --->    forward(2)
ipv4_src=10.0.0.3, state=2                                                  --->    forward(4)
'''

class OSTestFFSM(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OSTestFFSM, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        self.send_features_request(datapath)
        self.send_table_mod(datapath)

        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        self.add_flow(datapath)
        self.add_state_entry(datapath)
        time.sleep(5)
        self.del_state_entry(datapath)
        time.sleep(5)
        self.add_state_entry(datapath)
        

    def add_flow(self, datapath, table_miss=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # ARP packets flooding
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32760, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)


        match = parser.OFPMatch(
            ipv4_src="10.0.0.1", in_port=1, eth_type=0x0800)
        (flag, flag_mask) = parser.maskedflags("1*01",8)
        actions = [parser.OFPActionSetState(state=0xfffffffa,stage_id=1),
            parser.OFPActionSetFlag(flag, flag_mask)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions),
            parser.OFPInstructionGotoTable(1),
            parser.OFPInstructionWriteMetadata(64954, 0xffffffffffffffff)
            ]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(
            ipv4_src="10.0.0.1", eth_type=0x0800, metadata=64954, state=0xfffffffa, flags=parser.maskedflags("1*01",8))
        actions = [parser.OFPActionOutput(2)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=1,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(
            ipv4_src="10.0.0.3", in_port=3, eth_type=0x0800)

        inst = [parser.OFPInstructionGotoTable(1)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(
            ipv4_src="10.0.0.4", in_port=4, eth_type=0x0800)
        actions = [parser.OFPActionOutput(3)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(
            ipv4_src="10.0.0.3", eth_type=0x0800, state=2)
        actions = [parser.OFPActionOutput(4)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=1,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = parser.OFPMatch(
            ipv4_src="10.0.0.2", in_port=2, eth_type=0x0800)
        actions = [parser.OFPActionOutput(1)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)


    def send_table_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableMod(datapath, 1, ofp.OFPTC_TABLE_STATEFUL)
        datapath.send_msg(req)

    def send_features_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def add_state_entry(self, datapath):
        ofproto = datapath.ofproto
        state = datapath.ofproto_parser.OFPStateEntry(
            datapath, ofproto.OFPSC_ADD_FLOW_STATE, 4, 2, [10,0,0,3],
            cookie=0, cookie_mask=0, table_id=1)
        datapath.send_msg(state)

    def del_state_entry(self, datapath):
        ofproto = datapath.ofproto
        state = datapath.ofproto_parser.OFPStateEntry(
            datapath, ofproto.OFPSC_DEL_FLOW_STATE, 4, 2, [10,0,0,3],
            cookie=0, cookie_mask=0, table_id=1)
        datapath.send_msg(state)

    def send_key_lookup(self, datapath):
        ofp = datapath.ofproto
        key_lookup_extractor = datapath.ofproto_parser.OFPKeyExtract(
            datapath, ofp.OFPSC_SET_L_EXTRACTOR, 1, [ofp.OXM_OF_IPV4_SRC],table_id=1)
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        ofp = datapath.ofproto
        key_update_extractor = datapath.ofproto_parser.OFPKeyExtract(
            datapath, ofp.OFPSC_SET_U_EXTRACTOR, 1, [ofp.OXM_OF_IPV4_SRC],table_id=1)
        datapath.send_msg(key_update_extractor)
