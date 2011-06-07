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
from umit.inventory.common import AgentFields

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.internet.protocol import DatagramProtocol

import traceback
import json
from copy import copy


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
        fields = dict()
        try:
            fields[NotificationFields.source_host] =\
                    str(temp[AgentFields.source_host])

            fields[NotificationFields.timestamp] =\
                    float(temp[AgentFields.timestamp])

            fields[NotificationFields.protocol] = str(self.get_protocol_name())

            fields[NotificationFields.notification_type] =\
                    str(temp[AgentFields.message_type])

            fields[NotificationFields.description] =\
                    unicode(temp[AgentFields.message])

            fields[AgentNotificationFields.monitoring_module] =\
                    unicode(temp[AgentFields.monitoring_module])

            # TODO decide how to do add the dynamic fields to the
            # AgentNotificationFields definitions.
            for module_field in temp[AgentFields.module_fields].keys():
                fields[module_field] =\
                        temp[AgentFields.module_fields][module_field]
        except Exception, e:
            traceback.prin_exc()
            # TODO: Log this

        try:
            notification = AgentNotification(fields)
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



class AgentNotification(Notification):
    """ The notification class associated to this protocol """

    def get_name(self):
        return 'UmitAgentNotification'

    def get_fields_class(self):
        return AgentNotificationFields



class AgentNotificationFields(NotificationFields):
    """ The fields associated with the AgentNotification class. """

    names = copy(NotificationFields.names)
    types = copy(NotificationFields.types)

    monitoring_module = AgentFields.monitoring_module
    names.append(monitoring_module)

    types[AgentFields.monitoring_module] = unicode

    @staticmethod
    def get_names():
        return AgentNotificationFields.names

    @staticmethod
    def get_types():
        return AgentNotificationFields.types
