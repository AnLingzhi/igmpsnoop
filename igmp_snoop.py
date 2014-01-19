from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner

from pox.lib.packet.igmp import igmp as Igmp

import logging as logger

# IP protocol number
IGMP_PROTO = 2

class igmp_snoop_forward(DynamicPolicy):
    """
    Implement IGMP snooping for the topology's switches. This policy should be
    used in parallel with a policy that handles non-IP-multicast traffic.
    """
    # base policies are defined and documented in pyretic/core/language.py
    def __init__(self):
        # examine all IGMP packets
        self.query = match(protocol=IGMP_PROTO) >> packets()
        # keep track of group forwarding rules - need targeted deletion to
        # handle group leave requests
        self.group_rules = set()

        def track_group_membership(pkt):
            try:
                igmp = igmp_from_eth(pkt)
            except Exception as e:
                logger.exception(e)

            # Rule: if IP packet at this switch with this multicast address,
            # then forward to the host which sent the join message
            group_fwd = match(switch=pkt['switch'], dstip=igmp.address) >> \
                        fwd(pkt['port'])
            # matching on IP dest on layer 2 because we can.

            if igmp.ver_and_type in (Igmp.MEMBERSHIP_REPORT,
                                     Igmp.MEMBERSHIP_REPORT_V2):
                group_rules.add(group_fwd)
            elif igmp.ver_and_type == Igmp.LEAVE_GROUP_V2:
                try: 
                    group_rules.remove(group_fwd)
                except KeyError as e:
                    logger.exception(e)
            else: # uninteresting IGMP message
                pass

            self.policy = union(group_rules) + self.query

        self.query.register_callback(track_group_membership)
        super(igmp_snoop_forward, self).__init__(self.query)


def eth_payload(packet):
    # mostly taken from pyretic example "dpi.py"
    eth_bytes = [ord(b) for b in packet['raw']]
    return eth_bytes[packet['header_len']:]

WORDS_TO_BYTES = 4
def ip_payload(packet):
    ethPayload = eth_payload(packet)
    #ip_version = (ethPayload[0] & 0b11110000) >> 4
    #assert ip_version == 4 or ip_version == 127
    #ip_proto   = ethPayload[9]
    ihl = (ethPayload[0] & 0b00001111)
    ip_header_len = ihl * WORDS_TO_BYTES
    return ethPayload[ip_header_len:]

def igmp_from_eth(rawpacket):
    ipPayload = ip_payload(rawpacket)
    return Igmp(raw=ipPayload)

def main():
    # policy when this module is run as the main policy
    return igmp_snoop_forward() + mac_learner()

if __name__ == '__main__':
    main()
