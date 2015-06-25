import struct
from ryu.lib.pack_utils import msg_pack_into
from ryu.ofproto.ofproto_parser import StringifyMixin, MsgBase, msg_str_attr
import ryu.ofproto.ofproto_v1_3_parser as ofproto_parser
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.openstate_v1_0 as osproto

def OFPExpActionSetState(state, table_id, hard_timeout=0, idle_timeout=0, hard_rollback=0, idle_rollback=0, state_mask=0xffffffff):
    """ 
    Returns a Set state experimenter action

    This action applies the state. TO DO: look how deal with ofl msg instruction
    and also cls
    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    state            State instance
    state_mask       State mask
    table_id         Stage ID
    ================ ======================================================
    """
    act_type=osproto.OFPAT_EXP_SET_STATE
    data=struct.pack(osproto.OFP_EXP_ACTION_SET_STATE_PACK_STR, act_type, state, state_mask, table_id, hard_rollback, idle_rollback, hard_timeout*1000000, idle_timeout*1000000)
    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0xBEBABEBA, data=data)

def OFPExpActionSetFlag(flag, flag_mask=0xffffffff):
    """ 
    Returns a Set Flag experimenter action

    This action updates flags in the switch global state.
    
    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    flag             Flags value
    flag_mask        Mask value
    ================ ======================================================
    """
    act_type=osproto.OFPAT_EXP_SET_FLAG
    data=struct.pack(osproto.OFP_EXP_ACTION_SET_FLAG_PACK_STR, act_type, flag, flag_mask)
    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0XBEBABEBA, data=data)

def OFPExpMsgConfigureStatefulTable(datapath, stateful, table_id):
    command=osproto.OFPSC_STATEFUL_TABLE_CONFIG
    data=struct.pack(osproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(osproto.OFP_EXP_STATE_MOD_STATEFUL_TABLE_CONFIG_PACK_STR,table_id,stateful)
    
    exp_type=osproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgKeyExtract(datapath, command, fields, table_id):
    field_count=len(fields)
    data=struct.pack(osproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(osproto.OFP_EXP_STATE_MOD_EXTRACTOR_PACK_STR,table_id,field_count)
    field_extract_format='!I'

    if field_count <= osproto.MAX_FIELD_COUNT:
        for f in range(field_count):
            data+=struct.pack(field_extract_format,fields[f])
    else:
        LOG.error("OFPExpMsgKeyExtract: Number of fields given > MAX_FIELD_COUNT")
    
    exp_type=osproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgSetFlowState(datapath, state, keys, table_id, idle_timeout=0, idle_rollback=0, hard_timeout=0, hard_rollback=0, state_mask=0xffffffff):
    key_count=len(keys)
    command=osproto.OFPSC_EXP_SET_FLOW_STATE
    data=struct.pack(osproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(osproto.OFP_EXP_STATE_MOD_SET_FLOW_STATE_PACK_STR, table_id, key_count, state, state_mask, hard_rollback, idle_rollback, hard_timeout*1000000, idle_timeout*1000000)
    field_extract_format='!B'

    if key_count <= osproto.MAX_KEY_LEN:
        for f in range(key_count):
                data+=struct.pack(field_extract_format,keys[f])
    else:
        LOG.error("OFPExpMsgSetFlowState: Number of keys given > MAX_KEY_LEN")
    
    exp_type=osproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgDelFlowState(datapath, keys, table_id):
    key_count=len(keys)
    command=osproto.OFPSC_EXP_DEL_FLOW_STATE
    data=struct.pack(osproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(osproto.OFP_EXP_STATE_MOD_DEL_FLOW_STATE_PACK_STR,table_id,key_count)
    field_extract_format='!B'

    if key_count <= osproto.MAX_KEY_LEN:
        for f in range(key_count):
                data+=struct.pack(field_extract_format,keys[f])
    else:
        LOG.error("OFPExpMsgDelFlowState: Number of keys given > MAX_KEY_LEN")
    
    exp_type=osproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpSetGlobalState(datapath, flag, flag_mask=0xffffffff):
    data=struct.pack(osproto.OFP_EXP_STATE_MOD_PACK_STR, osproto.OFPSC_SET_GLOBAL_STATE)
    data+=struct.pack(osproto.OFP_EXP_STATE_MOD_SET_GLOBAL_STATE_PACK_STR,flag,flag_mask)
    
    exp_type=osproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpResetGlobalState(datapath):
    data=struct.pack(osproto.OFP_EXP_STATE_MOD_PACK_STR, osproto.OFPSC_RESET_GLOBAL_STATE)
    
    exp_type=osproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpStateStatsMultipartRequest(datapath, flags=0, table_id=ofproto.OFPTT_ALL, state=None, match=None):
    get_from_state = 1
    if state is None:
        get_from_state = 0
        state = 0
        
    if match is None:
        match = ofproto_parser.OFPMatch()

    data=bytearray()
    msg_pack_into(osproto.OFP_STATE_STATS_REQUEST_0_PACK_STR, data, 0, table_id, get_from_state, state)
    
    offset=osproto.OFP_STATE_STATS_REQUEST_0_SIZE
    match.serialize(data, offset)

    exp_type=osproto.OFPMP_EXP_STATE_STATS
    return ofproto_parser.OFPExperimenterStatsRequest(datapath=datapath, flags=flags, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpGlobalStateStatsMultipartRequest(datapath, flags=0):
    data=bytearray()

    exp_type=osproto.OFPMP_EXP_FLAGS_STATS
    return ofproto_parser.OFPExperimenterStatsRequest(datapath=datapath, flags=flags, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

class OFPStateEntry(object):
    def __init__(self, key_count=None, key=None, state=None):
        super(OFPStateEntry, self).__init__()
        
        self.key_count=key_count
        self.key = key
        self.state = state
    
    @classmethod
    def parser(cls, buf, offset):
        entry = OFPStateEntry()

        key_count = struct.unpack_from('!I', buf, offset)
        entry.key_count = key_count[0]
        offset += 4
        entry.key=[]
        if entry.key_count <= osproto.MAX_KEY_LEN:
            for f in range(entry.key_count):
                key=struct.unpack_from('!B',buf,offset,)
                entry.key.append(key[0])
                offset +=1
        offset += (osproto.MAX_KEY_LEN - entry.key_count)

        state = struct.unpack_from('!I', buf, offset)
        entry.state=state[0]
        offset += 4

        return entry

class OFPStateStats(StringifyMixin):
    def __init__(self, table_id=None, dur_sec=None, dur_nsec=None, field_count=None, fields=None, 
        entry=None,length=None, hard_rb=None, idle_rb=None, hard_to=None, idle_to=None):
        super(OFPStateStats, self).__init__()
        self.length = 0
        self.table_id = table_id
        self.dur_sec = dur_sec
        self.dur_nsec = dur_nsec
        self.field_count = field_count
        self.fields = fields
        self.entry = entry
        self.hard_to = hard_to
        self.hard_rb = hard_rb
        self.idle_to = idle_to
        self.hard_rb = hard_rb
        
    @classmethod
    def parser(cls, buf, offset):
        state_stats_list = []
        
        for i in range(len(buf)/osproto.OFP_STATE_STATS_SIZE):
            state_stats = cls()

            (state_stats.length, state_stats.table_id, state_stats.dur_sec,
                state_stats.dur_nsec, state_stats.field_count) = struct.unpack_from(
                osproto.OFP_STATE_STATS_0_PACK_STR, buf, offset)
            offset += osproto.OFP_STATE_STATS_0_SIZE

            state_stats.fields=[]
            field_extract_format='!I'
            if state_stats.field_count <= osproto.MAX_FIELD_COUNT:
                for f in range(state_stats.field_count):
                    field=struct.unpack_from(field_extract_format,buf,offset)
                    state_stats.fields.append(field[0])
                    offset +=4
            offset += ((osproto.MAX_FIELD_COUNT-state_stats.field_count)*4)
            state_stats.entry = OFPStateEntry.parser(buf, offset)
            offset += osproto.OFP_STATE_STATS_ENTRY_SIZE

            (state_stats.hard_rb, state_stats.idle_rb,state_stats.hard_to, state_stats.idle_to) = struct.unpack_from(
                osproto.OFP_STATE_STATS_1_PACK_STR, buf, offset)
            offset += osproto.OFP_STATE_STATS_1_SIZE
            state_stats_list.append(state_stats)

        return state_stats_list

class OFPGlobalStateStats(StringifyMixin):
    def __init__(self, flags=None):
        super(OFPGlobalStateStats, self).__init__()
        self.flags = flags
        
    @classmethod
    def parser(cls, buf, offset):
        global_state_stats = cls()

        (global_state_stats.flags, ) = struct.unpack_from('!4xI', buf, offset)

        return global_state_stats

def get_field_string(field,key,key_count,offset):
    if field==ofproto.OXM_OF_IN_PORT:
        if key_count!=0:
            length = 4
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0]
            return ("in_port=\"%d\""%(value),length)
        else:
            return ("in_port=*",0)
    elif field==ofproto.OXM_OF_IN_PHY_PORT:
        if key_count!=0:
            length = 4
            VLAN_VID_MASK = 0x0fff
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0] & VLAN_VID_MASK
            return ("in_phy_port=\"%d\""%(value),length)
        else:
            return ("in_phy_port=*",0)
    elif field==ofproto.OXM_OF_VLAN_VID:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("vlan_vid=\"%d\""%(value),length)
        else:
            return ("vlan_vid=*",0)
    elif field==ofproto.OXM_OF_VLAN_PCP:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x7
            return ("vlan_pcp=\"%d\""%(value),length)
        else:
            return ("vlan_pcp=*",0)
    elif field==ofproto.OXM_OF_ETH_TYPE:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("eth_type=\"%d\""%(value),length)
        else:
            return ("eth_type=*",0)
    elif field==ofproto.OXM_OF_TCP_SRC:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("tcp_src=\"%d\""%(value),length)
        else:
            return ("tcp_src=*",0)
    elif field==ofproto.OXM_OF_TCP_DST:
        if key_count!=0:
            length = 2
            print(key)
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("tcp_dst=\"%d\""%(value),length)
        else:
            return ("tcp_dst=*",0)
    elif field==ofproto.OXM_OF_UDP_SRC:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("udp_src=\"%d\""%(value),length)
        else:
            return ("udp_src=*",0)
    elif field==ofproto.OXM_OF_UDP_DST:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("udp_dst=\"%d\""%(value),length)
        else:
            return ("udp_dst=*",0)
    elif field==ofproto.OXM_OF_SCTP_SRC:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("sctp_src=\"%d\""%(value),length)
        else:
            return ("sctp_src=*",0)
    elif field==ofproto.OXM_OF_SCTP_DST:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("sctp_dst=\"%d\""%(value),length)
        else:
            return ("sctp_dst=*",0)
    elif field==ofproto.OXM_OF_ETH_SRC:
        if key_count!=0:
            length = 6
            return ("eth_src=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("eth_src=*",0)
    elif field==ofproto.OXM_OF_ETH_DST:
        if key_count!=0:
            length = 6
            return ("eth_dst=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("eth_dst=*",0)
    elif field==ofproto.OXM_OF_IPV4_SRC:
        if key_count!=0:
            length = 4
            return ("ipv4_src=\"%d.%d.%d.%d\""%(key[offset],key[offset+1],key[offset+2],key[offset+3]),length)
        else:
            return ("ipv4_src=*",0)
    elif field==ofproto.OXM_OF_IPV4_DST:
        if key_count!=0:
            length = 4
            return ("ipv4_dst=\"%d.%d.%d.%d\""%(key[offset],key[offset+1],key[offset+2],key[offset+3]),length)
        else:
            return ("ipv4_dst=*",0)
    elif field==ofproto.OXM_OF_IP_PROTO:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("ip_proto=\"%d\""%(value),length)
        else:
            return ("ip_proto=*",0)
    elif field==ofproto.OXM_OF_IP_DSCP:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x3f
            return ("ip_dscp=\"%d\""%(value),length)
        else:
            return ("ip_dscp=*",0)
    elif field==ofproto.OXM_OF_IP_ECN:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x3
            return ("ip_ecn=\"%d\""%(value),length)
        else:
            return ("ip_ecn=*",0)
    elif field==ofproto.OXM_OF_ICMPV4_TYPE:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("icmpv4_type=\"%d\""%(value),length)
        else:
            return ("icmpv4_type=*",0)
    elif field==ofproto.OXM_OF_ICMPV4_CODE:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("icmpv4_code=\"%d\""%(value),length)
        else:
            return ("icmpv4_code=*",0)
    elif field==ofproto.OXM_OF_ARP_SHA:
        if key_count!=0:
            length = 6
            return ("arp_sha=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("arp_sha=*",0)
    elif field==ofproto.OXM_OF_ARP_THA:
        if key_count!=0:
            length = 6
            return ("arp_tha=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("arp_tha=*",0)
    elif field==ofproto.OXM_OF_ARP_SPA:
        if key_count!=0:
            length = 4
            return ("arp_spa=\"%d.%d.%d.%d\""%(key[offset],key[offset+1],key[offset+2],key[offset+3]),length)
        else:
            return ("arp_spa=*",0)
    elif field==ofproto.OXM_OF_ARP_TPA:
        if key_count!=0:
            length = 4
            return ("arp_tpa=\"%d.%d.%d.%d\""%(key[offset],key[offset+1],key[offset+2],key[offset+3]),length)
        else:
            return ("arp_tpa=*",0)
    elif field==ofproto.OXM_OF_ARP_OP:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("arp_op=\"%d\""%(value),length)
        else:
            return ("arp_op=*",0)
    elif field==ofproto.OXM_OF_IPV6_SRC:
        if key_count!=0:
            length = 16
            value = []
            for q in range(8): 
                value[q]=format(struct.unpack('<H', array('B',key[offset:offset+2]))[0],'x')
                offset += 2
            return ("nw_src_ipv6=\"%s:%s:%s:%s:%s:%s:%s:%s\""%(value[0],value[1],value[2],value[3],value[4],value[5],value[6],value[7]),length)
        else:
            return ("nw_src_ipv6=*",0)
    elif field==ofproto.OXM_OF_IPV6_DST:
        if key_count!=0:
            length = 16
            value = []
            for q in range(8): 
                value.append(format(struct.unpack('<H', array('B',key[offset:offset+2]))[0],'x'))
                offset += 2
            return ("nw_dst_ipv6=\"%s:%s:%s:%s:%s:%s:%s:%s\""%(value[0],value[1],value[2],value[3],value[4],value[5],value[6],value[7]),length)
        else:
            return ("nw_dst_ipv6=*",0)
    elif field==ofproto.OXM_OF_IPV6_ND_TARGET:
        if key_count!=0:
            length = 16
            value = []
            for q in range(8): 
                value[q]=format(struct.unpack('<H', array('B',key[offset:offset+2]))[0],'x')
                offset += 2
            return ("ipv6_nd_target=\"%s:%s:%s:%s:%s:%s:%s:%s\""%(value[0],value[1],value[2],value[3],value[4],value[5],value[6],value[7]),length)
        else:
            return ("ipv6_nd_target=*",0)
    elif field==ofproto.OXM_OF_IPV6_ND_SLL:
        if key_count!=0:
            length = 6
            return ("ipv6_nd_sll=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("ipv6_nd_sll=*",0)
    elif field==ofproto.OXM_OF_IPV6_ND_TLL:
        if key_count!=0:
            length = 6
            return ("ipv6_nd_tll=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("ipv6_nd_tll=*",0)
    elif field==ofproto.OXM_OF_IPV6_FLABEL:
        if key_count!=0:
            length = 4
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0] & 0x000fffff
            return ("ipv6_flow_label=\"%d\""%(value),length)    
        else:
            return ("ipv6_flow_label=*",0)
    elif field==ofproto.OXM_OF_ICMPV6_TYPE:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("icmpv6_type=\"%d\""%(value),length)
        else:
            return ("icmpv6_type=*",0)
    elif field==ofproto.OXM_OF_ICMPV6_CODE:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("icmpv6_code=\"%d\""%(value),length)
        else:
            return ("icmpv6_code=*",0)
    elif field==ofproto.OXM_OF_MPLS_LABEL:
        if key_count!=0:
            length = 4
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0] & 0x000fffff
            return ("mpls_label=\"%d\""%(value),length)  
        else:
            return ("mpls_label=*",0)
    elif field==ofproto.OXM_OF_MPLS_TC:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x3
            return ("mpls_tc=\"%d\""%(value),length)
        else:
            return ("mpls_tc=*",0)
    elif field==ofproto.OXM_OF_MPLS_BOS:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x1
            return ("mpls_bos=\"%d\""%(value),length)
        else:
            return ("mpls_bos=*",0)
    elif field==ofproto.OXM_OF_PBB_ISID:
        if key_count!=0:
            length = 4
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0]
            return ("pbb_isid=\"%d\""%(value),length)  
        else:
            return ("pbb_isid=*",0)
    elif field==ofproto.OXM_OF_TUNNEL_ID:
        if key_count!=0:
            length = 8
            value = struct.unpack('<Q', array('B',key[offset:offset+length]))[0]
            return ("tunnel_id=\"%d\""%(value),length)
        else:
            return ("tunnel_id=*",0)
    elif field==ofproto.OXM_OF_IPV6_EXTHDR:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("ext_hdr=\"%d\""%(value),length)
        else:
            return ("ext_hdr=*",0)

def state_entry_key_to_str(extr,key,key_count):
    offset=0
    s=''
    for field in extr:
        (string,field_len) = get_field_string(field,key,key_count,offset)
        s += string
        offset += field_len
        if field!=extr[-1]:
            s += ","
    return s


'''
Flags are 32, numbered from 0 to 31 from right to left

maskedflags("0*1100")       -> **************************0*1100 -> (12,47)
maskedflags("0*1100",12)    -> ***************0*1100*********** -> (49152, 192512)

'''
def maskedflags(string,offset=0):
    import re
    str_len=len(string)
    if re.search('r[^01*]', string) or str_len>32 or str_len<1:
        print("ERROR: flags string can only contain 0,1 and * and must have at least 1 bit and at most 32 bits!")
        return (0,0)
    if offset>31 or offset<0:
        print("ERROR: offset must be in range 0-31!")
        return (0,0)
    if str_len+offset>32:
        print("ERROR: offset is too big")
        return (0,0)

    mask=['0']*32
    value=['0']*32

    for i in range(offset,str_len+offset):
        if not string[str_len-1+offset-i]=="*":
            mask[31-i]="1"
            value[31-i]=string[str_len-1+offset-i]
    mask=''.join(mask)
    value=''.join(value)
    return (int(value,2),int(mask,2))
'''
state field is 32bit long
Thanks to the mask we can divide the field in multiple substate matchable with masks.

substate(state,section,sec_count)
state = state to match
section = number of the selected subsection (starts from 1 from the right)
sec_count = number of how many subsection the state field has been divided

substate(5,2,4)   -> |********|********|00000101|********|-> (1280,16711680)

'''
def substate(state,section,sec_count):
    
    if not isinstance(state, int) or not isinstance(section, int) or not isinstance(sec_count, int):
        print("ERROR: parameters must be integers!")
        return(0,0)
    if state < 0 or section < 0 or sec_count < 0:
        print("ERROR: parameters must be positive!")
        return(0,0)
    if 32%sec_count != 0:
        print("ERROR: the number of sections must be a divisor of 32")
        return(0,0)
    section_len = 32/sec_count
    if state >= pow(2,section_len):
        print("ERROR: state exceed the section's length")
        return(0,0)
    if section not in range (1,sec_count+1):
        print("ERROR: section not exist. It must be between 1 and sec_count")
        return(0,0)

    sec_count = sec_count -1
    count = 1
    starting_point = section*section_len
    
    mask=['0']*32
    value=['0']*32
    bin_state=['0']*section_len
    
    state = bin(state)
    state = ''.join(state[2:])
    
    for i in range(0,len(state)):
        bin_state [section_len-1-i]= state[len(state)-1-i]
    
    for i in range(starting_point,starting_point+section_len):
        value[31-i]=bin_state[section_len - count]
        count = count + 1 
        mask[31-i]="1"
    
    mask=''.join(mask)
    value=''.join(value)
    return (int(value,2),int(mask,2))
