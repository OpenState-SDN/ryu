import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls

LOG = logging.getLogger('app.openstate.portknock')

""" Last port is the one to be opened after knoking all the others """
port_list = [10, 11, 12, 13, 22]
final_port = port_list[-1]
second_last_port =  port_list[-2]

LOG.info("Port knock sequence is %s" % port_list[0:-1])
LOG.info("Final port to open is %s" % port_list[-1])

class OSPortKnocking(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OSPortKnocking, self).__init__(*args, **kwargs)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):

		msg = ev.msg
		datapath = msg.datapath
		ofp = datapath.ofproto
		parser = datapath.ofproto_parser

		LOG.info("Configuring switch %d..." % datapath.id)

		""" Set table 0 as stateful """
		req = parser.OFPExpMsgConfigureStatefulTable(datapath=datapath,
													table_id=0,
													stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {ip_src} """
		req = parser.OFPExpMsgKeyExtract(datapath=datapath,
										command=ofp.OFPSC_EXP_SET_L_EXTRACTOR,
										fields=[ofp.OXM_OF_IPV4_SRC],
										table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {ip_src} (same as lookup) """
		req = parser.OFPExpMsgKeyExtract(datapath=datapath,
									command=ofp.OFPSC_EXP_SET_U_EXTRACTOR,
									fields=[ofp.OXM_OF_IPV4_SRC],
									table_id=0)
		datapath.send_msg(req)

		""" ARP packets flooding """
		match = parser.OFPMatch(eth_type=0x0806)
		actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
		self.add_flow(datapath=datapath, table_id=0, priority=100,
						match=match, actions=actions)

		""" Flow entries for port knocking """
		for i in range(len(port_list)):
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=17,
										state=i, udp_dst=port_list[i])

			if port_list[i] != final_port and port_list[i] != second_last_port:
				# If state not OPEN, set state and drop (implicit)
				actions = [parser.OFPExpActionSetState(state=i+1, table_id=0, idle_timeout=5)]		
			elif port_list[i] == second_last_port:
				# In the transaction to the OPEN state, the timeout is set to 10 sec
				actions = [parser.OFPExpActionSetState(state=i+1, table_id=0, idle_timeout=10)]
			else:
				actions = [parser.OFPActionOutput(2)]
			self.add_flow(datapath=datapath, table_id=0, priority=10,
							match=match, actions=actions)

		""" Get back to DEFAULT if wrong knock (UDP match, lowest priority) """
		match = parser.OFPMatch(eth_type=0x0800, ip_proto=17)
		actions = [parser.OFPExpActionSetState(state=0, table_id=0)]
		self.add_flow(datapath=datapath, table_id=0, priority=0,
						match=match, actions=actions)

		""" Test port 1300, always forward on port 2 """
		match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=1300)
		actions = [parser.OFPActionOutput(2)]
		self.add_flow(datapath=datapath, table_id=0, priority=10,
						match=match, actions=actions)


	def add_flow(self, datapath, table_id, priority, match, actions):
		ofp = datapath.ofproto
		parser = datapath.ofproto_parser
		inst = [parser.OFPInstructionActions(
				ofp.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)
