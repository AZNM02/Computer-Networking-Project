# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()


class Firewall(object):
    """
    A Firewall object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # add switch rules here
        # Allow any IPv4 to accept any IPv4 (ICMP)
        icmp_rule = of.ofp_flow_mod()
        icmp_rule.priority = 100
        icmp_rule.match.dl_type = 0x0800 # IPv4
        icmp_rule.match.nw_proto = 1 # ICMP
        icmp_rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(icmp_rule)
        # Allow any IP to accept any IP (ARP)
        arp_rule = of.ofp_flow_mod()
        arp_rule.match.dl_type = 0x0806 # ARP
        arp_rule.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(arp_rule)
        # Allow any IPv4 to drop any IPv4
        drop_rule = of.ofp_flow_mod()
        drop_rule.match.dl_type = 0x0800 # IPv4
        drop_rule.priority = 10
        self.connection.send(drop_rule)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print("Unhandled packet :" + str(packet.dump()))


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
