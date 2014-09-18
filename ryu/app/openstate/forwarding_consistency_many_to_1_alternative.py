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
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, \
    HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.topology import event

LOG = logging.getLogger('app.openstate.forwarding_consistency_1_to_many_alternative')

SWITCH_PORTS = 4

class OSLoadBalancing(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        LOG.info("OpenState Forwarding Consistency sample app initialized")
        LOG.info("Supporting MAX %d ports per switch" % SWITCH_PORTS)
        super(OSLoadBalancing, self).__init__(*args, **kwargs)
        self.mac_to_port = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        options ={1: self.one_to_many_switch,
                  2: self.middleswitch,
                  3: self.middleswitch,
                  4: self.middleswitch,
                  5: self.one_to_many_switch_right
        }

        options[datapath.id](datapath)


    def one_to_many_switch(self, datapath):
        self.send_features_request(datapath)
        self.send_group_mod_1(datapath)
        self.send_table_mod(datapath)

        self.send_key_lookup_1(datapath)
        self.send_key_update_1(datapath)

        # install table-miss flow entry (if no rule matching, send it to controller)
        # self.add_flow_1(datapath, True)
        # install other flow entries
        self.add_flow_1(datapath, False)

    def middleswitch(self, datapath):
        self.send_features_request(datapath)
        # install table-miss flow entry (if no rule matching, send it to controller)
        # self.add_flow_2(datapath, True)
        # install other flow entries
        self.add_flow_2(datapath, False)
    
    def one_to_many_switch_right(self, datapath):
        self.send_features_request(datapath)
        self.send_group_mod_2(datapath)
        self.send_table_mod(datapath)

        self.send_key_lookup_2(datapath)
        self.send_key_update_2(datapath)

        # install table-miss flow entry (if no rule matching, send it to controller)
        # self.add_flow_3(datapath, True)
        # install other flow entries
        self.add_flow_3(datapath, False)

    def add_flow_1(self, datapath, table_miss=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        LOG.info("Configuring flow table for switch %d" % datapath.id)     

        if table_miss:
            LOG.debug("Installing table miss...")
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

        else:

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

            
            # Reverse path flow
            for in_port in range(2, SWITCH_PORTS + 1):
                match = parser.OFPMatch(in_port=in_port)
                actions = [
                    parser.OFPActionOutput(1,0)]
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

            # the state of a flow is the selected output port for that flow
            for state in range(SWITCH_PORTS):
                if state == 0:
                    # if state=DEFAULT => send it to the first group entry in the group table
                    actions = [
                            parser.OFPActionGroup(1)]
                    match = parser.OFPMatch(
                            in_port=1, state=state, eth_type=0x800)
                else:
                    # state x means output port x+1
                    actions = [
                        parser.OFPActionOutput(state+1, 0),
                        parser.OFPActionSetState(state, 0)]
                    match = parser.OFPMatch(
                        in_port=1, state=state, eth_type=0x800)
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


    def add_flow_2(self, datapath, table_miss=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        LOG.info("Configuring flow table for switch %d" % datapath.id)     

        if table_miss:
            LOG.debug("Installing table miss...")
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

        else:

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
            
    def add_flow_3(self, datapath, table_miss=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        LOG.info("Configuring flow table for switch %d" % datapath.id)     

        if table_miss:
            LOG.debug("Installing table miss...")
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

        else:

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

            
            # forward path flow
            for in_port in range(1, SWITCH_PORTS):
                match = parser.OFPMatch(in_port=in_port)
                actions = [
                    parser.OFPActionOutput(4,0)]
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

            # the state of a flow is the selected output port for that flow
            for state in range(SWITCH_PORTS):
                if state == 0:
                    # if state=DEFAULT => send it to the first group entry in the group table
                    actions = [
                            parser.OFPActionGroup(1)]
                    match = parser.OFPMatch(
                            in_port=4, state=state, eth_type=0x800)
                else:
                    # state x means output port x+1
                    actions = [
                        parser.OFPActionOutput(state, 0),
                        parser.OFPActionSetState(state, 0)]
                    match = parser.OFPMatch(
                        in_port=4, state=state, eth_type=0x800)
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

    def send_group_mod_1(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            buckets = []
            # Action Bucket: <PWD port_i , SetState(i-1)
            for port in range(2,SWITCH_PORTS+1):
                max_len = 2000
                actions = [
                    ofp_parser.OFPActionOutput(port, max_len),
                    ofp_parser.OFPActionSetState(port-1, 0)]

                weight = 0
                watch_port = ofp.OFPP_ANY
                watch_group = ofp.OFPG_ANY
                buckets.append(ofp_parser.OFPBucket(weight, watch_port, watch_group,actions))

            group_id = 1
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                         ofp.OFPGT_RANDOM, group_id, buckets)
            datapath.send_msg(req)

    def send_group_mod_2(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            buckets = []
            # Action Bucket: <PWD port_i , SetState(i-1)
            for port in range(1,SWITCH_PORTS):
                max_len = 2000
                actions = [
                    ofp_parser.OFPActionOutput(port, max_len),
                    ofp_parser.OFPActionSetState(port, 0)]

                weight = 0
                watch_port = ofp.OFPP_ANY
                watch_group = ofp.OFPG_ANY
                buckets.append(ofp_parser.OFPBucket(weight, watch_port, watch_group,actions))

            group_id = 1
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                         ofp.OFPGT_RANDOM, group_id, buckets)
            datapath.send_msg(req)

    def send_table_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableMod(datapath, 0, ofp.OFPTC_TABLE_STATEFUL)
        datapath.send_msg(req)
    
    def send_features_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def send_key_lookup_1(self, datapath):
        ofp = datapath.ofproto
        key_lookup_extractor = datapath.ofproto_parser.OFPKeyExtract(datapath, ofp.OFPSC_SET_L_EXTRACTOR, 4, [ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST])
        datapath.send_msg(key_lookup_extractor)

    def send_key_update_1(self, datapath):
        ofp = datapath.ofproto
        key_update_extractor = datapath.ofproto_parser.OFPKeyExtract(datapath, ofp.OFPSC_SET_U_EXTRACTOR, 4, [ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST])
        datapath.send_msg(key_update_extractor)

    def send_key_lookup_2(self, datapath):
        ofp = datapath.ofproto
        key_lookup_extractor = datapath.ofproto_parser.OFPKeyExtract(datapath, ofp.OFPSC_SET_L_EXTRACTOR, 4, [ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST])
        datapath.send_msg(key_lookup_extractor)

    def send_key_update_2(self, datapath):
        ofp = datapath.ofproto
        key_update_extractor = datapath.ofproto_parser.OFPKeyExtract(datapath, ofp.OFPSC_SET_U_EXTRACTOR,  4, [ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST])
        datapath.send_msg(key_update_extractor)