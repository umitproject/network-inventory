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
from umit.inventory.server.Module import ServerModule
from umit.inventory.server.Notification import Notification
from umit.inventory.server.Notification import NotificationFields
import umit.inventory.server.Notification
from umit.inventory.common import AgentNotificationFields

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.internet.protocol import DatagramProtocol

import traceback
import json


class AgentListener(ListenerServerModule, ServerModule):

    # Options
    udp_port_option = 'listening_udp_port'
    ssl_port_option = 'listening_ssl_port'


    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)

        self.udp_port = int(self.options[AgentListener.udp_port_option])
        self.ssl_port = int(self.options[AgentListener.ssl_port_option])


    def get_name(self):
        return 'AgentListener'


    def get_protocol_name(self):
        return 'UmitAgent'


    def init_default_settings(self):
        self.options[AgentListener.udp_port_option] = '20000'
        self.options[AgentListener.ssl_port_option] = '20001'


    def receive_message(self, host, port, data):
        try:
            temp = json.loads(data)
        except Exception, e:
            traceback.print_exc()
            # TODO: Log this

        # Must be careful, as it may be invalid and not contain all the fields.
        standard_fields = dict()
        custom_fields = dict()
        try:
            standard_fields[NotificationFields.source_host] =\
                    temp[AgentNotificationFields.source_host]

            standard_fields[NotificationFields.timestamp] =\
                    temp[AgentNotificationFields.timestamp]

            standard_fields[NotificationFields.protocol] =\
                    self.get_protocol_name()

            standard_fields[NotificationFields.type] =\
                    temp[AgentNotificationFields.message_type]

            standard_fields[NotificationFields.description] =\
                    temp[AgentNotificationFields.message]

            custom_fields[AgentNotificationFields.monitoring_module] =\
                    temp[AgentNotificationFields.monitoring_module]
            custom_fields[AgentNotificationFields.module_fields] =\
                    temp[AgentNotificationFields.module_fields]
        except Exception, e:
            traceback.prin_exc()
            # TODO: Log this

        try:
            notification = Notification(standard_fields, custom_fields)
            self.shell.parse_notification(self.get_name(), notification)
        except Exception, e:
            traceback.print_exc()
            # TODO: Log this


    def listen(self):
        reactor.listenUDP(self.udp_port, AgentDatagramProtocol(self))
        # TODO: listen SSL



class AgentDatagramProtocol(DatagramProtocol):
    """ The protocol used when receiving messages from the Agents """

    def __init__(self, agent_listener):
        self.agent_listener = agent_listener


    def datagramReceived(self, data, (host, port)):
        self.agent_listener.receive_message(host, port, data)
