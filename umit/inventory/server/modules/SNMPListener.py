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
    check_community_string = 'check_comunity_string'


    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)

        self.port = int(self.options[SNMPListener.port_option])
        self.community_string = self.options[SNMPListener.community_string]
        self.check_community_string =\
                self.options[SNMPListener.check_community_string]


    def get_name(self):
        return 'SNMPListener'


    def get_protocol_name(self):
        return 'SNMP'


    def init_default_settings(self):
        self.options[SNMPListener.port_option] = '162'
        self.options[SNMPListener.community_string] = 'public'
        self.options[SNMPListener.check_community_string] = 'True'


    def receive_message(self, host, port, data):
        """ Called when we received a SNMP message on the configured port. """
        snmp_version = int(api.decodeMessageVersion(data))
        if snmp_version in api.protoModules:
            prot_module = api.protoModules[snmp_version]
        else:
            raise UnsupportedSNMPVersion(snmp_version)

        message, temp = decoder.decode(data, asn1Spec=prot_module.Message())

        # If configured, check if the community string matches
        recv_community = prot_module.apiMessage.getCommunity(message)
        if self.check_community_string and\
            recv_community != self.community_string:
            raise InvalidCommunityString(host, port, recv_community)

        recv_pdu = prot_module.apiMessage.getPDU(message)

        # Only accepting SNMP Trap PDU's
        if not recv_pdu.isSameTypeWith(prot_module.TrapPDU()):
            raise InvalidSNMPType(host, port)

        # Only supporting SNMPv1 and SNMPv2 at the moment
        if snmp_version == api.protoVersion1:
            self.parse_snmpv1_pdu(recv_pdu)
        elif snmp_version == api.protoVersion2:
            self.parse_snmpv2_pdu(recv_pdu)
        else:
            raise UnsupportedSNMPVersion(snmp_version)


    def parse_snmpv1_pdu(self, trap_pdu):
        """ Parses and saves a SNMPv1 Trap PDU """
        pass


    def parse_snmpv2_pdu(self, trap_pdu):
        """ Parses and saves a SNMPv2 Trap PDU """
        pass


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

class InvalidCommunityString(Exception):

    def __init__(self, host, port, comm_string):
        self.err_msg = 'Received %s community string from %s:%s' %\
                (str(comm_string), str(host), str(port))

    def __str__(self):
        return repr(self.err_msg)

class InvalidSNMPType(Exception):

    def __init__(self, host, port):
        self.err_msg = 'Only supporting TRAP PDU\'s. Source host: %s:%s' %\
                (str(host), str(port))

    def __str__(self):
        return repr(self.err_msg)
