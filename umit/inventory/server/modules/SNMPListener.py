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
import pyasn1.type.univ
import pyasn1.type.char
import pyasn1.type.useful

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
        print message

        # If configured, check if the community string matches
        recv_community = prot_module.apiMessage.getCommunity(message)
        print recv_community
        if self.check_community_string and\
            recv_community != self.community_string:
            raise InvalidCommunityString(host, port, recv_community)

        recv_pdu = prot_module.apiMessage.getPDU(message)

        # Only accepting SNMP Trap PDU's
        if not recv_pdu.isSameTypeWith(prot_module.TrapPDU()):
            raise InvalidSNMPType(host, port)

        # Only supporting SNMPv1 and SNMPv2 at the moment
        if snmp_version == api.protoVersion1:
            self.parse_snmpv1_pdu(prot_module, recv_pdu)
        elif snmp_version == api.protoVersion2c:
            self.parse_snmpv2_pdu(prot_module, recv_pdu, host)
        else:
            raise UnsupportedSNMPVersion(snmp_version)


    def parse_snmpv1_pdu(self, prot_module, trap_pdu):
        """ Parses and saves a SNMPv1 Trap PDU """

        # Get the general fields
        enterprise_oid = prot_module.apiTrapPDU.getEnterprise(trap_pdu)
        enterprise_oid = enterprise_oid.prettyPrint()
        generic_trap_id = prot_module.apiTrapPDU.getGenericTrap(trap_pdu)
        enterprise_trap_id = prot_module.apiTrapPDU.getSpecificTrap(trap_pdu)
        agent_address = prot_module.apiTrapPDU.getAgentAddr(trap_pdu)
        uptime = prot_module.apiTrapPDU.getTimeStamp(trap_pdu)

        # Parsing the agent address into a string
        agent_address_str = agent_address.prettyPrint()

        # Get the variables
        variables_dict = dict()
        variables = prot_module.apiTrapPDU.getVarBinds(trap_pdu)
        print variables

        for oid, value in variables:
            oid_str = oid.prettyPrint()
            try:
                converted_value = ASN1Type.convert_to_python_type(value)
            except Exception, e:
                #TODO log this
                traceback.print_exc()
                continue

            print '%s = %s (%s)' % (oid_str, converted_value,\
                    type(converted_value))
            variables_dict[oid_str] = converted_value

        print variables_dict
        # TODO parse to Notification object


    def parse_snmpv2_pdu(self, prot_module, trap_pdu, host):
        """ Parses and saves a SNMPv2 Trap PDU """

        trap_api = prot_module.apiTrapPDU
        var_binds = trap_api.getVarBinds(trap_pdu)

        # Here we will be saving the unknown variables.
        optional_parameters = dict()

        # Known variables.
        uptime = None
        source_host = None
        trap_oid = None
        trap_enterprise = None

        for var_bind in var_binds:
            # The key is the ObjectIdentifier which we will use as a string.
            key_raw = var_bind[0]
            key = var_bind[0].prettyPrint()
            # var_bind[1] is the value associated with var_bind[0]. Converting
            # to a Python raw type.
            value = ASN1Type.convert_to_python_type(var_bind[1])

            # Check for SNMPv2 General fields

            #TODO check why the community is also here. ignoring for now.
            if key_raw == trap_api.snmpTrapCommunity:
                continue

            if key_raw == trap_api.sysUpTime:
                uptime = value
                continue

            if key_raw == trap_api.snmpTrapAddress:
                source_host = value
                continue

            if key_raw == trap_api.snmpTrapOID:
                trap_oid = value
                continue

            if key_raw == trap_api.snmpTrapEnterprise:
                trap_enterprise = value
                continue

            # Optional parameter. Saving in specific dictionary
            optional_parameters[key] = value

        # If the host which emited it isn't remote, then the source address
        # is the one mentioned in the IP packet.
        if source_host == None:
            source_host = host

        print '----------------------------'
        print 'source_host: %s' % source_host
        print 'uptime: %s' % uptime
        print 'trap_oid: %s' % trap_oid
        print 'enterprise_oid: %s' % trap_enterprise
        print 'Variables:'
        for key in optional_parameters.keys():
            print '\t%s = %s (%s)' % (key, optional_parameters[key],\
                    type(optional_parameters[key]))

        # TODO parse to Notification object


    def listen(self):
        reactor.listenUDP(self.port, SNMPDatagramProtocol(self))



class ASN1Type:
    """ Simple ASN1 types used to determine the correct Python type """
    integer = pyasn1.type.univ.Integer()
    boolean = pyasn1.type.univ.Boolean()
    bitstring = pyasn1.type.univ.BitString()
    octetstring = pyasn1.type.univ.OctetString()
    null = pyasn1.type.univ.Null()
    oid = pyasn1.type.univ.ObjectIdentifier()
    real = pyasn1.type.univ.Real()


    @staticmethod
    def convert_to_python_type(asn1_value):
        """
        Checks the given asn1 value and makes the appropiate cast
        to a Python type.
        """
        # In PyASN1 the prettyPrint() method will return a string
        # representation of that object.
        # At the moment, the order of the if statements matters.

        # Try to get an int if possible. Considering various types
        # inheritance, this is the best way to go for indexing purposes.
        try:
            return int(asn1_value.prettyPrint())
        except:
            # Do nothing.
            pass

        if asn1_value.isSameTypeWith(ASN1Type.boolean):
            return bool(asn1_value.prettyPrint())

        if asn1_value.isSameTypeWith(ASN1Type.null):
            # TODO: Decide what to return here: A string describing that the
            # value is null or the python 'None-Type' None.
            return '[Empty]'

        if asn1_value.isSuperTypeOf(ASN1Type.integer):
            return int(asn1_value.prettyPrint())

        if asn1_value.isSameTypeWith(ASN1Type.bitstring) or\
           asn1_value.isSuperTypeOf(ASN1Type.octetstring) or\
           asn1_value.isSameTypeWith(ASN1Type.oid):
            return asn1_value.prettyPrint()

        if asn1_value.isSuperTypeOf(ASN1Type.real):
            return float(asn1_value.prettyPrint())

        return asn1_value.prettyPrint()



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
