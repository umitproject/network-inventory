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

from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.internet.protocol import DatagramProtocol

from pysnmp.proto import api
from pyasn1.codec.ber import decoder

import traceback


class SNMPListener(ListenerServerModule, ServerModule):

    # Options
    port_option = 'listening_port'
    community_string = 'community_string'


    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)

        self.port = int(self.options[SNMPListener.port_option])
        self.community_string = self.options[SNMPListener.community_string]


    def get_name(self):
        return 'SNMPListener'


    def get_protocol_name(self):
        return 'SNMP'


    def init_default_settings(self):
        self.options[SNMPListener.port_option] = '162'
        self.options[SNMPListener.community_string] = 'public'


    def receive_message(self, host, port, data):
        """ Called when we received a SNMP message on the configured port. """
        while data:
            snmp_version = int(api.decodeMessageVersion(data))
            if snmp_version in api.protoModules:
                protocol_module = api.protoModules[snmp_version]
            else:
                raise UnsupportedSNMPVersion(snmp_version)

            print snmp_version
            return



    def listen(self):
        reactor.listenUDP(self.port, SNMPDatagramProtocol(self))



class SNMPDatagramProtocol(DatagramProtocol):
    """ The protocol used when receiving messages from SNMP agents. """

    def __init__(self, snmp_listener):
        self.snmp_listener = snmp_listener


    def datagramReceived(self, data, (host, port)):
        try:
            self.snmp_listener.receive_message(host, port, data)
        except Exception, e:
            traceback.print_exc()
            # TODO log this



class SNMPNotification(Notification):
    """ The notification class for SNMP """

    def __init__(self, fields):
        Notification.__init__(self, fields)
        #TODO add the SNMP specific fields to the class.



class UnsupportedSNMPVersion(Exception):

    def __init__(self, snmp_version):
        self.err_msg = 'Only SNMPv1 and SNMPv2 supported. Received version: '\
                + str(snmp_version)

    def __str__(self):
        return repr(self.err_msg)

