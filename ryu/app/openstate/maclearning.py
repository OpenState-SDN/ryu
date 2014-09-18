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

LOG = logging.getLogger('app.openstate.maclearning')

SWITCH_PORTS = 4


class OSMacLearning(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        LOG.info("OpenState MAC Learning sample app initialized")
        LOG.info("Supporting MAX %d ports per switch" % SWITCH_PORTS)
        super(OSMacLearning, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        self.send_features_request(datapath)
        self.send_table_mod(datapath)

        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        self.add_flow(datapath, False)


    def add_flow(self, datapath, table_miss=False):
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

            '''

            Lookup-scope=ETH_DST
            Update-scope=ETH_SRC

            # the state of a flow is the port where a host can be reached

            match: state=0 & in_port=i  =>  action: set_state(i) & flood()
            match: state=j & in_port=i  =>  action: set_state(i) & output(j)

            '''

            for in_port in range(1, SWITCH_PORTS + 1):  # for each port (from 1 to #ports)
                LOG.info("Installing flow rule for port %d..." % in_port)
                for state in range(SWITCH_PORTS + 1):   # for each state (from 0 to #ports)

                    if state == 0:  # DEFAULT state
                        actions = [
                            parser.OFPActionOutput(
                                ofproto.OFPP_FLOOD),
                            parser.OFPActionSetState(in_port,0)]
                        match = parser.OFPMatch(
                            in_port=in_port, state=state)
                    
                    else:
                        actions = [
                           parser.OFPActionOutput(state, 0),
                           parser.OFPActionSetState(in_port,0)]
                        match = parser.OFPMatch(
                            in_port=in_port, state=state)
                    
                    inst = [parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(
                        datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                        command=ofproto.OFPFC_ADD, idle_timeout=0,
                        hard_timeout=0, priority=32768,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                        flags=0, match=match, instructions=inst)
                    datapath.send_msg(mod)

    def send_table_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPTableMod(datapath, 0, ofp.OFPTC_TABLE_STATEFUL)
        datapath.send_msg(req)

    def add_state_entry(self, datapath):
        ofproto = datapath.ofproto
        state = datapath.ofproto_parser.OFPStateEntry(
            datapath, ofproto.OFPSC_ADD_FLOW_STATE, 6, 4, [0,0,0,0,0,2],
            cookie=0, cookie_mask=0, table_id=0)
        datapath.send_msg(state)

    def send_features_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def send_key_lookup(self, datapath):
        ofp = datapath.ofproto

        key_lookup_extractor = datapath.ofproto_parser.OFPKeyExtract(
            datapath, ofp.OFPSC_SET_L_EXTRACTOR, 1, [ofp.OXM_OF_ETH_DST])
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        ofp = datapath.ofproto

        key_update_extractor = datapath.ofproto_parser.OFPKeyExtract(
            datapath, ofp.OFPSC_SET_U_EXTRACTOR, 1, [ofp.OXM_OF_ETH_SRC])
        datapath.send_msg(key_update_extractor)

