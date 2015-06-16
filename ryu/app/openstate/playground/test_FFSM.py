
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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.topology import event
import time
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osp
import ryu.ofproto.openstate_v1_0_parser as osparser

'''
Applicazione di test che fa uso di Global States (flags), Flow States e Metadata contemporaneamente e dei comandi OFPSC_EXP_SET_FLOW_STATE e OFPSC_EXP_DEL_FLOW_STATE

Ci sono 6 host:
h1 e h2 si pingano sempre
h3 e h4 non si pingano per i primi 5 secondi, poi riescono sempre
h5 e h6 si pingano sempre

TABLE 0 (stateless)

ipv4_src=10.0.0.1, in_port=1    --->    SetState(state=0xfffffffa,table_id=1), SetFlag("1*01********"), WriteMetadata(64954), GotoTable(1)
ipv4_src=10.0.0.2, in_port=2    --->    forward(1)
ipv4_src=10.0.0.3, in_port=3    --->    GotoTable(1)
ipv4_src=10.0.0.4, in_port=4    --->    forward(3)
ipv4_src=10.0.0.5, in_port=5    --->    SetState(state = 3, state_mask = 255, table_id=1), GotoTable(1)
ipv4_src=10.0.0.6, in_port=6    --->    forward(5)

TABLE 1 (stateful) Lookup-scope=Update-scope=OXM_OF_IPV4_SRC)

ipv4_src=10.0.0.1, metadata=64954, flags="1*01********", state=0xfffffffa   --->    forward(2)
ipv4_src=10.0.0.3, state=2                                                  --->    forward(4)
ipv4_src=10.0.0.5, state=3, state_mask = 255                                --->    forward(6)
'''

class OSTestFFSM(app_manager.RyuApp):
    OFP_VERSIONS = [ofp.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OSTestFFSM, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def state_stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if ev.msg.body.exp_type==0:
            # EXP_STATE_STATS
            print("OFPExpStateStatsMultipartReply received:")
            stats = osparser.OFPStateStats.parser(ev.msg.body.data, offset=0)
            for stat in stats:
                extractor = [ofp.OXM_OF_IPV4_SRC]
                print('{table_id=%s, key={%s}, state=%d, dur_sec=%d, dur_nsec=%d, idle_to=%d, idle_rb=%d, hard_to=%d, hard_rb=%d}' 
                        %(stat.table_id,osparser.state_entry_key_to_str(extractor,stat.entry.key,stat.entry.key_count),
                            stat.entry.state,stat.dur_sec,stat.dur_nsec,stat.idle_to,stat.idle_rb,stat.hard_to,stat.hard_rb))

        elif ev.msg.body.exp_type==1:
            # EXP_GLOBAL_STATE_STATS
            print("OFPExpGlobalStateStatsMultipartReply received:")
            stat = osparser.OFPGlobalStateStats.parser(ev.msg.body.data, offset=0)
            print("{global_states="+'{:032b}'.format(stat.flags)+"}")


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        self.send_features_request(datapath)
        self.send_table_mod(datapath)

        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        
        self.add_flow(datapath)
        
        self.test_set_global_states(datapath)
        time.sleep(5)
        self.test_reset_global_states(datapath)
        self.set_substate_entry(datapath)
        time.sleep(5)
        self.set_substate_entry2(datapath)
        
        self.set_state_entry(datapath)
        time.sleep(5)
        self.del_state_entry(datapath)
        time.sleep(5)
        self.set_state_entry(datapath)
        self.send_state_stats_request(datapath)
        self.send_global_state_stats_request(datapath)

    def add_flow(self, datapath, table_miss=False):

        # ARP packets flooding
        match = ofparser.OFPMatch(eth_type=0x0806)
        actions = [
            ofparser.OFPActionOutput(ofp.OFPP_FLOOD)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32760, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)


        match = ofparser.OFPMatch(
            ipv4_src="10.0.0.1", in_port=1, eth_type=0x0800)
        (flag, flag_mask) = osparser.maskedflags("1*01",8)
        (state, state_mask) = osparser.substate(state=4294967290,section=1,sec_count=1)
        actions = [osparser.OFPExpActionSetState(state=state,state_mask=state_mask,table_id=1),
            osparser.OFPExpActionSetFlag(flag=flag,flag_mask=flag_mask)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions),
            ofparser.OFPInstructionGotoTable(1),
            ofparser.OFPInstructionWriteMetadata(64954, 0xffffffffffffffff)
            ]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(
            ipv4_src="10.0.0.1", in_port=1, eth_type=0x0800, metadata=64954, state=osparser.substate(state=4294967290,section=1,sec_count=1), flags=osparser.maskedflags("1*01",8))
        actions = [ofparser.OFPActionOutput(2)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=1,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(
            ipv4_src="10.0.0.5", in_port=5, eth_type=0x0800)
        (state, state_mask) = osparser.substate(state=3,section=1,sec_count=4)
        actions = [osparser.OFPExpActionSetState(state=state,state_mask=state_mask,table_id=1)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions),
            ofparser.OFPInstructionGotoTable(1)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(
            ipv4_src="10.0.0.5", in_port=5, eth_type=0x0800, state=osparser.substate(state=3,section=1,sec_count=4))
        actions = [ofparser.OFPActionOutput(6)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=1,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(
            ipv4_src="10.0.0.3", in_port=3, eth_type=0x0800)

        inst = [ofparser.OFPInstructionGotoTable(1)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(
            ipv4_src="10.0.0.4", in_port=4, eth_type=0x0800)
        actions = [ofparser.OFPActionOutput(3)]
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

        match = ofparser.OFPMatch(
            ipv4_src="10.0.0.6", in_port=6, eth_type=0x0800)
        actions = [ofparser.OFPActionOutput(5)]
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

        match = ofparser.OFPMatch(
            ipv4_src="10.0.0.3", in_port=3, eth_type=0x0800, state=osparser.substate(state=2,section=1,sec_count=1))
        actions = [ofparser.OFPActionOutput(4)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=1,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(
            ipv4_src="10.0.0.2", in_port=2, eth_type=0x0800)
        actions = [ofparser.OFPActionOutput(1)]
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


    def send_table_mod(self, datapath):
        req = osparser.OFPExpMsgConfigureStatefulTable(datapath=datapath, table_id=1, stateful=1)
        datapath.send_msg(req)

    def send_features_request(self, datapath):
        req = ofparser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def test_set_global_states(self, datapath):
        msg = osparser.OFPExpSetGlobalState(datapath=datapath, flag=18)
        datapath.send_msg(msg)
        self.send_global_state_stats_request(datapath)

    def test_reset_global_states(self, datapath):
        msg = osparser.OFPExpResetGlobalState(datapath=datapath)
        datapath.send_msg(msg)
        self.send_global_state_stats_request(datapath)

    def set_substate_entry(self, datapath):
        (state, state_mask) = osparser.substate(state=2,section=4,sec_count=4)
        msg = osparser.OFPExpMsgSetFlowState(
            datapath=datapath, state=state, state_mask=state_mask, keys=[10,0,0,5], table_id=1)
        datapath.send_msg(msg)

    def set_substate_entry2(self, datapath):
        (state, state_mask) = osparser.substate(state=6,section=3,sec_count=4)
        msg = osparser.OFPExpMsgSetFlowState(datapath=datapath, state=state, state_mask=state_mask, keys=[10,0,0,5], table_id=1)
        datapath.send_msg(msg)

    def set_state_entry(self, datapath):
        (state, state_mask) = osparser.substate(state=2,section=1,sec_count=1)
        msg = osparser.OFPExpMsgSetFlowState(datapath=datapath, state=state, state_mask=state_mask, keys=[10,0,0,3], table_id=1)
        datapath.send_msg(msg)

    def del_state_entry(self, datapath):
        (state, state_mask) = osparser.substate(state=2,section=1,sec_count=1)
        msg = osparser.OFPExpMsgDelFlowState(datapath=datapath, keys=[10,0,0,3], table_id=1)
        datapath.send_msg(msg)

    def send_key_lookup(self, datapath):
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(
            datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofp.OXM_OF_IPV4_SRC], table_id=1)
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        key_update_extractor = osparser.OFPExpMsgKeyExtract(
            datapath=datapath, command=osp.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofp.OXM_OF_IPV4_SRC], table_id=1)
        datapath.send_msg(key_update_extractor)

    def send_state_stats_request(self, datapath):
        req = osparser.OFPExpStateStatsMultipartRequest(datapath=datapath)
        datapath.send_msg(req)
        #match = ofp.OFPMatch(ipv4_src="10.0.0.2")
        #req = osp.OFPExpStateStatsMultipartRequest(datapath=datapath, table_id=ofp.OFPTT_ALL, match=match)
        #req = osp.OFPExpStateStatsMultipartRequest(datapath=datapath, table_id=ofp.OFPTT_ALL, state=768)
        #req = osp.OFPExpStateStatsMultipartRequest(datapath=datapath, match=None)
        #datapath.send_msg(req)

    def send_global_state_stats_request(self, datapath):
        req = osparser.OFPExpGlobalStateStatsMultipartRequest(datapath=datapath)
        datapath.send_msg(req)