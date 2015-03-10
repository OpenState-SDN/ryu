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

        '''
        Test da fare:

        [STATE]

        1) ping con match su state settato con azione OFPExpMsgSetStateEntry
        2) ping con match su state settato con messaggio SET_STATE
        3) Set state action must be performed onto a stateful stage (run-time check)
        4) Set state action must be performed onto a stage with stage_id less or equal than the number of pipeline's tables (install-time check, TODO!)
        5) State mod msg extractor: field_count must be consistent with the number of fields provided in fields
        6) State mod msg extractor: "lookup-scope and update-scope must provide same length keys"
        7) State mod add flow: key_count must be consistent with the number of fields provided in key
        8) State mod add flow: must be executed onto a stage with stage_id less or equal than the number of pipeline's tables

        '''

        ''' [TEST 1]
        mininet> h1 ping -c5 h2
        si dovrebbe perdere solo il primo ping '''
        #self.test1(datapath)

        ''' [TEST 2]
        mininet> h2 ping -c5 h4
        si dovrebbe pingare al 100% '''
        #self.test2(datapath)   

        ''' [TEST 3]
        mininet> h1 ping -c5 h2
        NON si dovrebbero pingare pero' si dovrebbe poter installare la regola'''
        #self.test3(datapath)   

        ''' [TEST 4]
        mininet> h1 ping -c5 h2
        NON si dovrebbe riuscire nemmeno ad installare la regola (TODO!)'''
        #self.test4(datapath)   

        ''' [TEST 5]
        NON si dovrebbe poter mandare il messaggio (TODO!)'''
        #self.test5(datapath)   

        ''' [TEST 6]
        NON si dovrebbe poter mandare il messaggio (TODO!)'''
        #self.test6(datapath)   

        ''' [TEST 7]
        c
        '''
        #self.test7(datapath)   

        
        ''' [TEST 8]
        dovrebbe tornare un errore (type=1,code=9))'''
        #self.test8(datapath)


        '''
        [FLAGS]

        1) ping con match su exact flags
        2) ping con match su flags con maschera
        3) Set flags action con flags
        4) Set flags action con flags con maschera
        5) Flag mod msg con flags
        6) Flag mod msg con flags con maschera

        '''
        
        '''
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
        
        # mininet> h5 ping -c5 h6
        # si dovrebbe poter pingare al 100%
        (flag, flag_mask) = parser.maskedflags("1001")
        msg = datapath.ofproto_parser.OFPExpMsgFlagMod(datapath, ofproto.OFPSC_EXP_MODIFY_FLAGS, flag, flag_mask)
        datapath.send_msg(msg)

        actions = [parser.OFPActionOutput(6,0)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,flags=parser.maskedflags("1001"),in_port=5)
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(5,0)]
        match = parser.OFPMatch(in_port=6)
        self.add_flow(datapath, 200, match, actions)
        '''


        '''
        # Azione SetFlag esatta
        # mininet> h5 ping -c5 h6
        # si dovrebbe poter pingare al 2o
        actions = [parser.OFPActionOutput(6,0)]
        match = parser.OFPMatch(in_port=5,flags=32)
        self.add_flow(datapath, 150, match, actions)

        actions = [parser.OFPExpActionSetFlag(value=32)]
        match = parser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(5,0)]
        match = parser.OFPMatch(in_port=6)
        self.add_flow(datapath, 200, match, actions)
        '''


        
        # Azione SetFlag con mask
        # mininet> h5 ping -c5 h6
        # si dovrebbe poter pingare al 2o

        (flag, flag_mask) = parser.maskedflags("1*1*1*1*1*1*1*1*0*0*1*1*1*1*1*1*")
        actions = [parser.OFPActionOutput(6,0)]
        match = parser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1,flags=parser.maskedflags("1*1*1*1*1*1*1*1*0*0*1*1*1*1*1*1*"))
        #match = parser.OFPMatch(in_port=5,flags=2863311530)
        self.add_flow(datapath, 150, match, actions)

        msg = datapath.ofproto_parser.OFPExpMsgFlagMod(datapath, ofproto.OFPSC_EXP_MODIFY_FLAGS, flag, flag_mask)
        datapath.send_msg(msg)

        actions = [parser.OFPExpActionSetFlag(flag, flag_mask)]
        actions = [parser.OFPExpActionSetFlag(2863311530)]
        match = parser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        #self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(5,0)]
        match = parser.OFPMatch(in_port=6)
        self.add_flow(datapath, 200, match, actions)
        
        # mininet> h2 ping -c5 h4
        # si dovrebbe poter pingare al 100%

        '''


        actions = [parser.OFPActionOutput(4,0)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,state=88,in_port=2)
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(in_port=4)
        self.add_flow(datapath, 200, match, actions)
        

        # regole per testare l'output di DPCTL

        actions = [parser.OFPExpActionSetFlag(value=3640)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,in_port=7)
        self.add_flow(datapath, 350, match, actions)

        actions = [parser.OFPExpActionSetFlag(flag, flag_mask)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,in_port=7)
        self.add_flow(datapath, 300, match, actions)    

        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(eth_type=0x800,ip_proto=1,state=2,in_port=1,flags=50)
        self.add_flow(datapath, 100, match, actions)      
        
        # experimenter_id=0x000026e1
        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(in_port=1,state=6)
        self.add_flow(datapath, 150, match, actions)

        actions = [parser.OFPExpActionSetState(state=6,stage_id=0)]
        match = parser.OFPMatch(in_port=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(1,0)]
        match = parser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)

        # h1 ping h2
        
        actions = [parser.OFPActionOutput(1,0)]
        match = parser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)
        
        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(in_port=1)
        self.add_flow(datapath, 200, match, actions)
        '''

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
        key_lookup_extractor = datapath.ofproto_parser.OFPExpMsgKeyExtract(datapath, ofp.OFPSC_EXP_SET_L_EXTRACTOR, 2, [ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST])
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        ofp = datapath.ofproto
        key_update_extractor = datapath.ofproto_parser.OFPExpMsgKeyExtract(datapath, ofp.OFPSC_EXP_SET_U_EXTRACTOR, 2, [ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST])
        datapath.send_msg(key_update_extractor)

    def test1(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(in_port=1,state=6)
        self.add_flow(datapath, 150, match, actions)

        actions = [parser.OFPExpActionSetState(state=6,stage_id=0)]
        match = parser.OFPMatch(in_port=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(1,0)]
        match = parser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)


    def test2(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        state = datapath.ofproto_parser.OFPExpMsgSetStateEntry(datapath, ofproto.OFPSC_EXP_ADD_FLOW_STATE, 12, 88, [0,0,0,0,0,2,0,0,0,0,0,4],cookie=0, cookie_mask=0, table_id=0)
        datapath.send_msg(state)

        actions = [parser.OFPActionOutput(4,0)]
        match = parser.OFPMatch(eth_type=0x800,state=88,in_port=2)
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(in_port=4)
        self.add_flow(datapath, 200, match, actions)

    def test3(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(in_port=1,state=6)
        self.add_flow(datapath, 150, match, actions)

        actions = [parser.OFPExpActionSetState(state=6,stage_id=10)]
        match = parser.OFPMatch(in_port=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(1,0)]
        match = parser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)

    def test4(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        actions = [parser.OFPActionOutput(2,0)]
        match = parser.OFPMatch(in_port=1,state=6)
        self.add_flow(datapath, 150, match, actions)

        actions = [parser.OFPExpActionSetState(state=6,stage_id=1000)]
        match = parser.OFPMatch(in_port=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [parser.OFPActionOutput(1,0)]
        match = parser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)

    def test5(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        ofp = datapath.ofproto
        key_lookup_extractor = datapath.ofproto_parser.OFPExpMsgKeyExtract(datapath, ofp.OFPSC_EXP_SET_L_EXTRACTOR, 3, [ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST])
        datapath.send_msg(key_lookup_extractor)

    def test6(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        ofp = datapath.ofproto
        key_lookup_extractor = datapath.ofproto_parser.OFPExpMsgKeyExtract(datapath, ofp.OFPSC_EXP_SET_L_EXTRACTOR, 2, [ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST])
        datapath.send_msg(key_lookup_extractor)
        key_lookup_extractor = datapath.ofproto_parser.OFPExpMsgKeyExtract(datapath, ofp.OFPSC_EXP_SET_U_EXTRACTOR, 1, [ofp.OXM_OF_ETH_SRC])
        datapath.send_msg(key_lookup_extractor)

    def test7(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        state = datapath.ofproto_parser.OFPExpMsgSetStateEntry(datapath, ofproto.OFPSC_EXP_ADD_FLOW_STATE, 12, 88, [0,0,0,0,0,2,0,0,0,0,0,4,8],cookie=0, cookie_mask=0, table_id=0)
        datapath.send_msg(state)

    def test8(self,datapath):
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser
        state = datapath.ofproto_parser.OFPExpMsgSetStateEntry(datapath, ofproto.OFPSC_EXP_ADD_FLOW_STATE, 12, 88, [0,0,0,0,0,2,0,0,0,0,0,4],cookie=0, cookie_mask=0, table_id=1000)
        datapath.send_msg(state)