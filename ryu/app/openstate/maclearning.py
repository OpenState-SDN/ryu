import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls

LOG = logging.getLogger('app.openstate.maclearning')

# Number of switch ports
N = 4

LOG.info("Support max %d ports per switch" % N)

class OSMacLearning(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OSMacLearning, self).__init__(*args, **kwargs)

	def add_flow(self, datapath, table_id, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		if len(actions) > 0:
			inst = [parser.OFPInstructionActions(
					ofproto.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event):

		""" Switche sent his features, check if OpenState supported """
		msg = event.msg
		datapath = msg.datapath
		ofp = datapath.ofproto
		parser = datapath.ofproto_parser

		LOG.info("Configuring switch %d..." % datapath.id)

		""" Set table 0 as stateful """
		req = parser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {eth_dst} """
		req = parser.OFPExpMsgKeyExtract(datapath=datapath,
				command=ofp.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofp.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = parser.OFPExpMsgKeyExtract(datapath=datapath,
				command=ofp.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofp.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		# for each input port, for each state
		for i in range(1, N+1):
			for s in range(N+1):
				match = parser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofp.OFPP_FLOOD
				else:
					out_port = s
				actions = [parser.OFPExpActionSetState(state=i, table_id=0, hard_timeout=10),
							parser.OFPActionOutput(out_port)]
				self.add_flow(datapath=datapath, table_id=0, priority=0,
								match=match, actions=actions)

		""" Need to drop some packets for DEMO puporses only (avoid learning before manual send_eth)"""
		#ARP packets
		# LOG.info("WARN: ARP packets will be dropped on switch %d" % datapath.id)
		# match = parser.OFPMatch(eth_type=0x0806)
		# actions = []
		# self.add_flow(datapath=datapath, table_id=0, priority=100,
		# 				match=match, actions=actions)

		#IPv6 packets
		# #LOG.info("WARN: IPv6 packets will be dropped on switch %d" % datapath.id)
		# match = parser.OFPMatch(eth_type=0x86dd)
		# actions = []
		# self.add_flow(datapath=datapath, table_id=0, priority=100,
		# 				match=match, actions=actions)

