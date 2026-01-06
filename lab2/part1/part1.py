#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI


class part1_topo(Topo):
    def build(self):
        # switch1 = self.addSwitch('switchname')
        s1 = self.addSwitch('s1')
        # host1 = self.addHost('hostname')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        # self.addLink(hostname,switchname)
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


topos = {"part1": part1_topo}

if __name__ == "__main__":
    t = part1_topo()
    net = Mininet(topo=t, controller=None)
    net.start()
    CLI(net)
    net.stop()