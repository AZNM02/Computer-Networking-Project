from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

# IP addresses
H10_IP = IPAddr("10.0.1.10")
H20_IP = IPAddr("10.0.2.20")
H30_IP = IPAddr("10.0.3.30")
SERV1_IP = IPAddr("10.0.4.10")
HNOTRUST_IP = IPAddr("172.16.10.100")

# Cores21 gateway addresses and ports
GATEWAY_IPS = {
    IPAddr("10.0.1.1"): 1,
    IPAddr("10.0.2.1"): 2,
    IPAddr("10.0.3.1"): 3,
    IPAddr("10.0.4.1"): 4,
    IPAddr("172.16.10.1"): 5,
}

# Router MAC per port (arbitrary, but must be consistent)
ROUTER_MACS = {
    1: EthAddr("00:00:00:00:21:01"),
    2: EthAddr("00:00:00:00:21:02"),
    3: EthAddr("00:00:00:00:21:03"),
    4: EthAddr("00:00:00:00:21:04"),
    5: EthAddr("00:00:00:00:21:05"),
}


class Part4Controller(object):
    """
    One instance of this class is created for each switch.
    """

    def __init__(self, connection):
        self.connection = connection

        # Bind PacketIn
        connection.addListeners(self)

        self.dpid = connection.dpid
        log.info("Switch %s connected (dpid=%s)", connection, self.dpid)

        if self.dpid == 1:
            self.s1_setup()
        elif self.dpid == 2:
            self.s2_setup()
        elif self.dpid == 3:
            self.s3_setup()
        elif self.dpid == 21:
            self._init_core_state()
            self.cores21_setup()
        elif self.dpid == 31:
            self.dcs31_setup()
        else:
            log.error("Unknown switch with dpid %s", self.dpid)

    def _init_core_state(self):
        # Learned hosts: ip -> (port, mac)
        self.ip_table = {}
        # Track which routes we've already installed
        self.installed_routes = set()

    # Helper to install a flow
    def _send_flow_mod(self, flow_mod):
        self.connection.send(flow_mod)

    # Edge switches: s1, s2, s3, dcs31
    def _edge_setup(self):
        # Allow / flood all ARP
        fm = of.ofp_flow_mod()
        fm.priority = 20
        fm.match.dl_type = ethernet.ARP_TYPE
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self._send_flow_mod(fm)

        # Allow / flood all IPv4 (any protocol)
        fm = of.ofp_flow_mod()
        fm.priority = 10
        fm.match.dl_type = ethernet.IP_TYPE
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

    def cores21_setup(self):
        conn = self.connection

        # 1) Block ALL IPv4 traffic from hnotrust1 to serv1
        fm = of.ofp_flow_mod()
        fm.priority = 200
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.nw_src = HNOTRUST_IP
        fm.match.nw_dst = SERV1_IP
        conn.send(fm)

        # 2) Block ICMP from hnotrust1 to any internal host
        protected = [H10_IP, H20_IP, H30_IP, SERV1_IP]
        for ip in protected:
            fm = of.ofp_flow_mod()
            fm.priority = 180
            fm.match.dl_type = ethernet.IP_TYPE
            fm.match.nw_proto = 1  # ICMP
            fm.match.nw_src = HNOTRUST_IP
            fm.match.nw_dst = ip
            conn.send(fm)

        log.info("Installed core firewall rules on cores21")

    def _learn_host(self, ip, mac, port):
        if ip in GATEWAY_IPS:
            return

        if ip in self.ip_table:
            existing_port, existing_mac = self.ip_table[ip]
            
            if existing_port != port:
                log.warning("Ignoring packet from %s on new port %s (already learned on %s)",
                            ip, port, existing_port)
                return 
            
            if existing_mac != mac:
                self.ip_table[ip] = (port, mac)
            
            return
        
        log.debug("Learned new host %s -> port %s, mac %s", ip, port, mac)
        self.ip_table[ip] = (port, mac)
        
        self._maybe_install_route(ip)

    def _maybe_install_route(self, dst_ip):
        if dst_ip not in self.ip_table:
            return
        if dst_ip in self.installed_routes:
            return

        port, dst_mac = self.ip_table[dst_ip]
        router_mac = ROUTER_MACS.get(port)
        if router_mac is None:
            log.error("No router MAC defined for port %s", port)
            return

        fm = of.ofp_flow_mod()
        fm.priority = 50
        fm.match.dl_type = ethernet.IP_TYPE
        fm.match.nw_dst = dst_ip
        fm.actions.append(of.ofp_action_dl_addr.set_src(router_mac))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=port))
        self.connection.send(fm)

        self.installed_routes.add(dst_ip)
        log.debug("Installed route for %s out port %s", dst_ip, port)

    def _handle_arp(self, event, packet):
        arp_packet = packet.find('arp')
        if arp_packet is None:
            return

        in_port = event.port
        sender_ip = arp_packet.protosrc
        sender_mac = arp_packet.hwsrc
        target_ip = arp_packet.protodst

        if sender_ip != 0:
            self._learn_host(sender_ip, sender_mac, in_port)

        # Respond to ARP requests for gateway IPs
        if arp_packet.opcode == arp.REQUEST:
            if target_ip in GATEWAY_IPS:
                out_port = GATEWAY_IPS[target_ip]
                router_mac = ROUTER_MACS.get(out_port)
                if router_mac is None:
                    log.error("No router MAC defined for gateway port %s (target %s)", out_port, target_ip)
                    return

                reply = arp()
                reply.hwtype = arp_packet.hwtype
                reply.prototype = arp_packet.prototype
                reply.hwlen = arp_packet.hwlen
                reply.protolen = arp_packet.protolen
                reply.opcode = arp.REPLY
                reply.hwdst = sender_mac
                reply.protodst = sender_ip
                reply.hwsrc = router_mac
                reply.protosrc = target_ip

                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = sender_mac
                ether.src = router_mac
                ether.payload = reply

                self.resend_packet(ether.pack(), in_port)
                log.debug("Sent ARP reply for %s to %s via port %s", target_ip,
                        sender_ip, in_port)
            if target_ip in self.ip_table:
                known_port, known_mac = self.ip_table[target_ip]
                router_mac = ROUTER_MACS.get(in_port)
                if router_mac is None:
                    router_mac = ROUTER_MACS.get(known_port)

                if router_mac is None:
                    log.error("No router MAC available to proxy-reply for ARP request for %s", target_ip)
                    return

                reply = arp()
                reply.hwtype = arp_packet.hwtype
                reply.prototype = arp_packet.prototype
                reply.hwlen = arp_packet.hwlen
                reply.protolen = arp_packet.protolen
                reply.opcode = arp.REPLY
                reply.hwdst = sender_mac
                reply.protodst = sender_ip
                reply.hwsrc = known_mac
                reply.protosrc = target_ip

                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = sender_mac
                ether.src = router_mac
                ether.payload = reply

                self.resend_packet(ether.pack(), in_port)
                log.debug("Proxy-replied ARP for %s -> told %s that %s is at %s (sent on port %s)",
                        target_ip, sender_ip, target_ip, known_mac, in_port)
                return

            # 3) Otherwise: we don't know the target; let the switch/controller behavior remain (no flooding across subnets)
            log.debug("ARP request for unknown target %s from %s on port %s; waiting to learn", target_ip, sender_ip, in_port)
            
        elif arp_packet.opcode == arp.REPLY:
            # Learning already handled; no forwarding needed.
            pass

    def _handle_ipv4(self, event, packet):
        ip_packet = packet.find('ipv4')
        if ip_packet is None:
            return

        src_ip = ip_packet.srcip
        dst_ip = ip_packet.dstip
        src_mac = packet.src
        in_port = event.port

        if src_ip != 0:
            self._learn_host(src_ip, src_mac, in_port)

        if dst_ip not in self.ip_table:
            log.debug("No route yet for %s; waiting for ARP learning", dst_ip)
            return

        port, dst_mac = self.ip_table[dst_ip]
        router_mac = ROUTER_MACS.get(port)
        if router_mac is None:
            log.error("No router MAC defined for port %s", port)
            return

        self._maybe_install_route(dst_ip)

        packet.src = router_mac
        packet.dst = dst_mac
        log.debug("Forwarding IPv4 packet %s -> %s via port %s",
                  src_ip, dst_ip, port)
        self.resend_packet(packet.pack(), port)

    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    # PacketIn handler
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet on dpid %s", self.dpid)
            return

        if self.dpid != 21:
            log.debug("Unhandled packet on non-core switch %s: %s",
                      self.dpid, packet.dump())
            return

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet)
        elif packet.type == ethernet.IP_TYPE:
            self._handle_ipv4(event, packet)
        else:
            log.debug("Unhandled packet type %s on cores21", packet.type)


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s", event.connection)
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)


