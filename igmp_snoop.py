from pyretic.lib.corelib import if_
from pyretic.lib.std import fwd, passthrough
from pyretic.lib.query import match, DynamicPolicy

from pox.lib.packet.packet import Packet


# IP protocol number
IGMP_PROTO = 2

# we create a new dynamic policy class with the name "act_like_switch"
class igmp_snoop(DynamicPolicy):
    """
    Implement learning-switch-like behavior.
    """
    # Pyretic predicates and policies are defined and documented in
    # pyretic/core/language.py
    def __init__(self):
        self.join_filter = match(protocol=IGMP_PROTO)
        self.query = packets()

        self.joins = []

        self.multi_filter = match(dstip=MULTICAST_CIDR)

        def track_joins(pkt):
            print(pkt)
            self.joins.append(pkt)
            sys.exit(0)

            # update the dynamic policy to forward and query
            # (each dynamic policy has a member 'policy'. whenever this member
            # is assigned, the dynamic policy updates itself)
            self.policy = self.forward + self.query

        # learn_from_a_packet is called back every time query sees a new packet
        self.query.register_callback(learn_from_a_packet)

        # finally, initialize the dynamic policy 
        super(act_like_switch,self).__init__(self.forward + self.query)


def main():
    ## The main method returns the policy that will be run  
    return act_like_switch()

