import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osp
import ryu.ofproto.openstate_v1_0_parser as osparser

LOG = logging.getLogger('app.openstate.maclearning')

# Number of switch ports
N = 4

LOG.info("Support max %d ports per switch" % N)

class OSMacLearning(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OSMacLearning, self).__init__(*args, **kwargs)

	def add_flow(self, datapath, table_id, priority, match, actions):
		if len(actions) > 0:
			inst = [ofparser.OFPInstructionActions(
					ofp.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event):

		""" Switche sent his features, check if OpenState supported """
		msg = event.msg
		datapath = msg.datapath

		LOG.info("Configuring switch %d..." % datapath.id)

		""" Set table 0 as stateful """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {eth_dst} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osp.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofp.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osp.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofp.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		# for each input port, for each state
		for i in range(1, N+1):
			for s in range(N+1):
				match = ofparser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofp.OFPP_FLOOD
				else:
					out_port = s
				actions = [osparser.OFPExpActionSetState(state=i, table_id=0, hard_timeout=10),
							ofparser.OFPActionOutput(out_port)]
				self.add_flow(datapath=datapath, table_id=0, priority=0,
								match=match, actions=actions)

		""" Need to drop some packets for DEMO puporses only (avoid learning before manual send_eth)"""
		#ARP packets
		# LOG.info("WARN: ARP packets will be dropped on switch %d" % datapath.id)
		# match = ofparser.OFPMatch(eth_type=0x0806)
		# actions = []
		# self.add_flow(datapath=datapath, table_id=0, priority=100,
		# 				match=match, actions=actions)

		#IPv6 packets
		# #LOG.info("WARN: IPv6 packets will be dropped on switch %d" % datapath.id)
		# match = ofparser.OFPMatch(eth_type=0x86dd)
		# actions = []
		# self.add_flow(datapath=datapath, table_id=0, priority=100,
		# 				match=match, actions=actions)

