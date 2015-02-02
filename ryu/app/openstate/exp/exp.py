# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        # mininet> h1 ping -c5 h2
        # si dovrebbe perdere solo il primo ping
        (flag, flag_mask) = parser.maskedflags("1*1*1*1*1*1*1")
        actions = [parser.OFPExpActionSetState(state=2,stage_id=0),parser.OFPExpActionSetFlag(flag, flag_mask)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,in_port=1)
        self.add_flow(datapath, 0, match, actions)

        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,state=2,in_port=1,flags=parser.maskedflags("1*1*1*1*1*1*1"))
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(1,0)]
        match = parser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)

        # mininet> h3 ping -c5 h4
        # si dovrebbe poter pingare al 100%

        state = datapath.ofproto_parser.OFPExpMsgSetStateEntry(datapath, ofproto.OFPSC_ADD_FLOW_STATE, 12, 88, [0,0,0,0,0,3,0,0,0,0,0,4],cookie=0, cookie_mask=0, table_id=0)
        datapath.send_msg(state)

        actions = [parser.OFPActionOutput(4,0)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,state=88,in_port=3)
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(3,0)]
        match = parser.OFPMatch(in_port=4)
        self.add_flow(datapath, 200, match, actions)

        # regole per testare l'output di DPCTL

        actions = [parser.OFPExpActionSetFlag(value=3640)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,in_port=5)
        self.add_flow(datapath, 350, match, actions)

        actions = [parser.OFPExpActionSetFlag(flag, flag_mask)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,in_port=5)
        self.add_flow(datapath, 300, match, actions)    

        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,state=2,in_port=1,flags=50)
        self.add_flow(datapath, 100, match, actions)      

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=priority, buffer_id=ofproto.OFP_NO_BUFFER,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_table_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableMod(datapath, 0, ofp.OFPTC_TABLE_STATEFUL)
        datapath.send_msg(req)

    def send_key_lookup(self, datapath):
        ofp = datapath.ofproto
        key_lookup_extractor = datapath.ofproto_parser.OFPExpMsgKeyExtract(datapath, ofp.OFPSC_SET_L_EXTRACTOR, 2, [ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST])
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        ofp = datapath.ofproto
        key_update_extractor = datapath.ofproto_parser.OFPExpMsgKeyExtract(datapath, ofp.OFPSC_SET_U_EXTRACTOR, 2, [ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST])
        datapath.send_msg(key_update_extractor)