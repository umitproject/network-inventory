# Copyright (C) 2011 Adriano Monteiro Marques.
#
# Author: Dragos Dena <dragos.dena@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


from umit.inventory.server.Core import ServerShell
from umit.inventory.server.Module import ListenerServerModule

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.internet.protocol import DatagramProtocol

class AgentListener(ListenerServerModule):

    # Options
    udp_port_option = 'ListeningUDPPort'
    ssl_port_option = 'ListeningSSLPort'


    def __init__(self, configs, shell):
        ListenerServerModule.__init__(self, configs, shell)

        self.udp_port = int(self.options[AgentListener.udp_port_option])
        self.ssl_port = int(self.options[AgentListener.ssl_port_option])


    def get_name(self):
        return 'AgentListener'


    def init_default_settings(self):
        self.options[AgentListener.udp_port_option] = '20000'
        self.options[AgentListener.ssl_port_option] = '20001'


    def receive_message(self, host, port, data):
        # TODO: Eventual parsing.
        self.shell.save_message(data)


    def listen(self):
        reactor.listenUDP(self.udp_port, AgentDatagramProtocol(self))
        # TODO: listen SSL



class AgentDatagramProtocol(DatagramProtocol):
    """ The protocol used when receiving messages from the Agents """

    def __init__(self, agent_listener):
        self.agent_listener = agent_listener


    def datagramReceived(self, data, (host, port)):
        self.agent_listener.receive_message(host, port, data)
