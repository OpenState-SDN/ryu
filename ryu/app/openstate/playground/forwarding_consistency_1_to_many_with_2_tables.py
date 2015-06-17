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
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osp
import ryu.ofproto.openstate_v1_0_parser as osparser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.topology import event

LOG = logging.getLogger('app.openstate.forwarding_consistency_1_to_many')

SWITCH_PORTS = 4

class OSLoadBalancing(app_manager.RyuApp):
    OFP_VERSIONS = [ofp.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        LOG.info("OpenState Forwarding Consistency sample app initialized")
        LOG.info("Supporting MAX %d ports per switch" % SWITCH_PORTS)
        super(OSLoadBalancing, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        self.send_features_request(datapath)
        self.send_group_mod(datapath)
        self.send_table_mod(datapath)

        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        # install table-miss flow entry (if no rule matching, send it to controller)
        # self.add_flow(datapath, True)

        # install other flow entries
        self.add_flow(datapath, False)

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
        
        With respect to basic application, the first table write the action set, while the second apply it.
        We want to test the SetState() parametrization.
        '''
        
    def add_flow(self, datapath, table_miss=False):
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

            # the state of a flow is the selected output port for that flow
            for state in range(SWITCH_PORTS):
                if state == 0:
                    # if state=DEFAULT => send it to the first group entry in the group table
                    actions = [
                            ofparser.OFPActionGroup(1)]
                    match = ofparser.OFPMatch(
                            in_port=1, state=state, eth_type=0x800, ip_proto=6)
                else:
                    # state x means output port x+1
                    dest_ip="10.0.0."+str(state+1)
                    dest_eth="00:00:00:00:00:0"+str(state+1)
                    dest_tcp=(state+1)*100
                    actions = [
                        osparser.OFPExpActionSetState(state=state, table_id=0),
                        ofparser.OFPActionSetField(ipv4_dst=dest_ip),
                        ofparser.OFPActionSetField(eth_dst=dest_eth),
                        ofparser.OFPActionSetField(tcp_dst=dest_tcp),
                        ofparser.OFPActionOutput(state+1, 0)]
                    match = ofparser.OFPMatch(
                        in_port=1, state=state, eth_type=0x800, ip_proto=6)
                inst = [
                    ofparser.OFPInstructionActions(
                        ofp.OFPIT_WRITE_ACTIONS, actions),
                    ofparser.OFPInstructionGotoTable(1)]
                mod = ofparser.OFPFlowMod(
                    datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                    command=ofp.OFPFC_ADD, idle_timeout=0,
                    hard_timeout=0, priority=32767,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    flags=0, match=match, instructions=inst)
                datapath.send_msg(mod)

            # Table 1 entry
            match = ofparser.OFPMatch()
            inst = []
            mod = ofparser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=1,
                command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=32767, buffer_id=ofp.OFP_NO_BUFFER,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                flags=0, match=match, instructions=inst)
            datapath.send_msg(mod)

    def send_group_mod(self, datapath):
            buckets = []
            # Action Bucket: <PWD port_i , SetState(i-1)
            for port in range(2,SWITCH_PORTS+1):
                max_len = 2000
                dest_ip="10.0.0."+str(port)
                dest_eth="00:00:00:00:00:0"+str(port)
                dest_tcp=(port)*100
                actions = [
                    osparser.OFPExpActionSetState(state=port-1, table_id=0),
                    ofparser.OFPActionSetField(ipv4_dst=dest_ip),
                    ofparser.OFPActionSetField(eth_dst=dest_eth),
                    ofparser.OFPActionSetField(tcp_dst=dest_tcp),
                    ofparser.OFPActionOutput(port, max_len)]
                
                weight = 100
                watch_port = ofp.OFPP_ANY
                watch_group = ofp.OFPG_ANY
                buckets.append(ofparser.OFPBucket(weight, watch_port, watch_group,actions))
                #buckets.append(ofparser.OFPBucket(actions))

            group_id = 1
            req = ofparser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                         ofp.OFPGT_SELECT, group_id, buckets)
            datapath.send_msg(req)

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