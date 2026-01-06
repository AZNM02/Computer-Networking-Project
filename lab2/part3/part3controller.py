from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr

log = core.getLogger()

# IP addresses
H10_IP       = IPAddr("10.0.1.10")
H20_IP       = IPAddr("10.0.2.20")
H30_IP       = IPAddr("10.0.3.30")
SERV1_IP     = IPAddr("10.0.4.10")
HNOTRUST_IP  = IPAddr("172.16.10.100")


class Part3Controller(object):
    """
    One instance of this class is created for each switch.
    """

    def __init__(self, connection):
        self.connection = connection

        # Bind PacketIn (we shouldn't get many if rules are correct)
        connection.addListeners(self)

        dpid = connection.dpid
        log.info("Switch %s connected (dpid=%s)", connection, dpid)

        if dpid == 1:
            self.s1_setup()
        elif dpid == 2:
            self.s2_setup()
        elif dpid == 3:
            self.s3_setup()
        elif dpid == 21:
            self.cores21_setup()
        elif dpid == 31:
            self.dcs31_setup()
        else:
            log.error("Unknown switch with dpid %s", dpid)

    # Helper to install a flow
    def _send_flow_mod(self, flow_mod):
        self.connection.send(flow_mod)

    # Edge switches: s1, s2, s3, dcs31
    # We can simply flood ARP and IPv4 like in Part 2.
    def _edge_setup(self):
        # Allow / flood all ARP
        fm = of.ofp_flow_mod()
        fm.priority = 20
        fm.match.dl_type = 0x0806         
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self._send_flow_mod(fm)

        # Allow / flood all IPv4 (any protocol)
        fm = of.ofp_flow_mod()
        fm.priority = 10
        fm.match.dl_type = 0x0800        
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self._send_flow_mod(fm)

    def s1_setup(self):
        self._edge_setup()

    def s2_setup(self):
        self._edge_setup()

    def s3_setup(self):
        self._edge_setup()

    def dcs31_setup(self):
        self._edge_setup()

    # Core router: cores21
    #  - Flood ARP
    #  - Route IPv4 based on destination IP to specific ports
    #  - Block:
    #       * all IP from hnotrust1 -> serv1
    #       * all ICMP from hnotrust1 -> any internal host
    def cores21_setup(self):
        conn = self.connection

        # ARP: flood everywhere
        fm = of.ofp_flow_mod()
        fm.priority = 20
        fm.match.dl_type = 0x0806          
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        conn.send(fm)

        # 1) Block ALL IPv4 traffic from hnotrust1 to serv1
        fm = of.ofp_flow_mod()
        fm.priority = 200
        fm.match.dl_type = 0x0800          
        fm.match.nw_src = HNOTRUST_IP
        fm.match.nw_dst = SERV1_IP
        # No actions -> drop
        conn.send(fm)

        # 2) Block ICMP from hnotrust1 to any internal host
        protected = [H10_IP, H20_IP, H30_IP, SERV1_IP]
        for ip in protected:
            fm = of.ofp_flow_mod()
            fm.priority = 180
            fm.match.dl_type = 0x0800      
            fm.match.nw_proto = 1        
            fm.match.nw_src = HNOTRUST_IP
            fm.match.nw_dst = ip
            # No actions -> drop
            conn.send(fm)

        # ROUTING RULES (normal priority) 
        # Port mapping on cores21 (from part3.py link order):
        #   port 1 -> s1      -> h10 (10.0.1.10)
        #   port 2 -> s2      -> h20 (10.0.2.20)
        #   port 3 -> s3      -> h30 (10.0.3.30)
        #   port 4 -> dcs31   -> serv1 (10.0.4.10)
        #   port 5 -> hnotrust1 (172.16.10.100)

        routes = [
            (H10_IP,      1),
            (H20_IP,      2),
            (H30_IP,      3),
            (SERV1_IP,    4),
            (HNOTRUST_IP, 5),
        ]

        for dst_ip, out_port in routes:
            fm = of.ofp_flow_mod()
            fm.priority = 50
            fm.match.dl_type = 0x0800      # IPv4
            fm.match.nw_dst = dst_ip
            fm.actions.append(of.ofp_action_output(port=out_port))
            conn.send(fm)

        log.info("Installed core routing and firewall rules on cores21")

    # PacketIn handler (mostly for debugging; rules should handle traffic)
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        log.debug("Unhandled packet on dpid %s: %s",
                  self.connection.dpid, packet.dump())


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s", event.connection)
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
