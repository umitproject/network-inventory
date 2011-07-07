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


from umit.inventory.server.Module import ListenerServerModule
from umit.inventory.server.Module import ServerModule
from umit.inventory.server.Notification import Notification
from umit.inventory.server.Notification import NotificationFields
from umit.inventory.common import NotificationTypes

from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol

from pysnmp.proto import api
from pysnmp.proto.mpmod.rfc3412 import SNMPv3Message, ScopedPDU
from pyasn1.codec.ber import decoder
import pyasn1.type.univ
from pysnmp.proto.secmod.rfc3414 import auth, priv, localkey

import traceback
from copy import copy
import time
import logging
import socket


class SNMPListener(ListenerServerModule, ServerModule):

    # Options
    port_option = 'listening_port'
    community_string = 'community_string'
    check_community_string = 'check_comunity_string'


    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)

        # The users dict (USM)
        self.users = dict()

        # Get the configurations
        self.port = int(self.options[SNMPListener.port_option])
        self.community_string = self.options[SNMPListener.community_string]
        self.check_community_string =\
                self.options[SNMPListener.check_community_string]


    def get_name(self):
        return 'SNMPListener'


    def get_protocol_name(self):
        return 'SNMP'


    def init_database_operations(self):
        """
        Called when we should init database operations. Will use this method
        to initialise the USM.
        """
        db_entries = self.shell.database.find(SNMPv3User.collection_name)
        for user_entry in db_entries:
            try:
                user_obj = SNMPv3User(user_entry)
            except:
                continue

            self.users[user_obj.user_name] = user_obj

        # TODO: delete this after testing is done:
        test_user = SNMPv3User(user_name='test_user',\
                auth_mode=SNMPv3User.hmac_md5_auth,\
                priv_mode=SNMPv3User.des_priv,\
                auth_pass='auth_pass', priv_pass='priv_pass')
        self.add_snmpv3_user(test_user)


    def init_default_settings(self):
        self.options[SNMPListener.port_option] = '162'
        self.options[SNMPListener.community_string] = 'public'
        self.options[SNMPListener.check_community_string] = 'True'


    def receive_message(self, host, port, data):
        """ Called when we received a SNMP message on the configured port. """
        snmp_version = int(api.decodeMessageVersion(data))
        if snmp_version in api.protoModules:
            prot_module = api.protoModules[snmp_version]
        elif snmp_version == 3:
            self.parse_snmpv3_trap(data, host)
            return
        else:
            raise UnsupportedSNMPVersion(snmp_version)

        message, temp = decoder.decode(data, asn1Spec=prot_module.Message())
        # print message

        # If configured, check if the community string matches
        recv_community = prot_module.apiMessage.getCommunity(message)
        # print recv_community
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

        for oid, value in variables:
            oid_str = oid.prettyPrint()
            try:
                converted_value = ASN1Type.convert_to_python_type(value)
            except Exception, e:
                #TODO log this
                traceback.print_exc()
                continue

            variables_dict[oid_str] = converted_value

        # Parse to Notification object
        fields = dict()
        try:
            # SNMPv1 specific fields
            fields[SNMPv1NotificationFields.generic_trap_id] =\
                    int(generic_trap_id)
            fields[SNMPv1NotificationFields.enterprise_trap_id] =\
                    int(enterprise_trap_id)
            fields[SNMPv1NotificationFields.enterprise_oid] =\
                    str(enterprise_oid)
            fields[SNMPv1NotificationFields.uptime] = int(uptime)

            # Notification general fields
            # Will fill: source_host_ipv4, source_host_ipv6, hostname
            SNMPUtils.fill_fields_with_host_info(fields, agent_address_str)
            fields[NotificationFields.timestamp] = float(time.time())
            fields[NotificationFields.protocol] = str(self.get_protocol_name())
            fields[NotificationFields.description] =\
                    unicode(SNMPUtils.parse_description(variables_dict))
            fields[NotificationFields.short_description] = u'SNMPv1 Trap'
            fields[NotificationFields.is_report] = False
            fields[NotificationFields.notification_type] =\
                    str(SNMPUtils.parse_type(generic_trap_id))

            # Add the variables to the fields.
            # TODO: May need some methods to ensure entity inheritance
            for variable_key in variables_dict.keys():
                # Replacing dots with '_'. TODO: better way for this
                fields_key = variable_key.replace('.', '_')
                fields[fields_key] = variables_dict[variable_key]

            # Forward to the Shell
            notification = SNMPv1Notification(fields)
            self.shell.parse_notification(self.get_name(), notification)
        except Exception, e:
            # TODO log this
            traceback.print_exc()


    def parse_snmpv2_pdu(self, prot_module, trap_pdu, host):
        """ Parses and saves a SNMPv2 Trap PDU """

        trap_api = prot_module.apiTrapPDU
        var_binds = trap_api.getVarBinds(trap_pdu)

        # Here we will be saving the unknown variables.
        optional_parameters = dict()

        # Known variables.
        uptime = -1
        source_host = None
        trap_oid = ''
        trap_enterprise = ''

        for var_bind in var_binds:
            # The key is the ObjectIdentifier which we will use as a string.
            key_raw = var_bind[0]
            key = var_bind[0].prettyPrint()
            # var_bind[1] is the value associated with var_bind[0]. Converting
            # to a Python raw type.
            try:
                value = ASN1Type.convert_to_python_type(var_bind[1])
            except Exception, e:
                # TODO log this
                traceback.print_exc()
                continue

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

        # If the host which emitted it isn't remote, then the source address
        # is the one mentioned in the IP packet.
        if source_host is None:
            source_host = host

        # TODO delete this
        print '----------------------------'
        print 'source_host: %s' % source_host
        print 'uptime: %s' % uptime
        print 'trap_oid: %s' % trap_oid
        print 'enterprise_oid: %s' % trap_enterprise
        print 'Variables:'

        for key in optional_parameters.keys():
            print '\t%s = %s (%s)' % (key, optional_parameters[key],\
                    type(optional_parameters[key]))
        # TODO until here

        # Parse to a Notification object
        fields = dict()
        try:
            # SNMPv2c specific fields
            fields[SNMPv2cNotificationFields.uptime] = uptime
            fields[SNMPv2cNotificationFields.trap_oid] = str(trap_oid)
            fields[SNMPv2cNotificationFields.enterprise_oid] =\
                    str(trap_enterprise)

            # General notification fields
            # Will fill: source_host_ipv4, source_host_ipv6, hostname
            SNMPUtils.fill_fields_with_host_info(fields, host)

            fields[NotificationFields.timestamp] = float(time.time())
            fields[NotificationFields.protocol] = str(self.get_protocol_name())
            fields[NotificationFields.description] =\
                    unicode(SNMPUtils.parse_description(optional_parameters))
            fields[NotificationFields.short_description] =\
                    u'SNMPv2c/SNMPv3 Notification'
            fields[NotificationFields.is_report] = False
            fields[NotificationFields.notification_type] =\
                    str(NotificationTypes.unknown)

            # Add the variables to the fields.
            # TODO: May need some methods to ensure entity inheritance
            for variable_key in optional_parameters.keys():
                # TODO: better way for this
                fields_key = variable_key.replace('.', '_')
                fields[fields_key] = optional_parameters[variable_key]

            # Forward to the Shell
            notification = SNMPv2cNotification(fields)
            self.shell.parse_notification(self.get_name(), notification)
        except Exception, e:
            # TODO log this
            traceback.print_exc()


    def parse_snmpv3_trap(self, trap_data, host):
        """
        Parses a SNMPv3 trap. It will first authenticate/decrypt as
        configured, then it will parse the PDU using the
        parse_snmpv2_pdu() method.
        """
        message, temp = decoder.decode(trap_data, asn1Spec=SNMPv3Message())

        # Trap notification main sections
        header_data = message.getComponentByPosition(1)
        security_param = message.getComponentByPosition(2)
        security_param = decoder.decode(security_param)[0]

        # Get the header relevant data
        flags = header_data.getComponentByPosition(2)
        security_model = header_data.getComponentByPosition(3)

        # Get if the message is authenticated and encrypted from the flags
        for ch in flags:
            flags = ord(ch)
            break
        is_auth = (0x01 & flags) != 0
        is_priv = (0x02 & flags) != 0

        # Get the relevant security parameters
        authoritative_engine_id = security_param.getComponentByPosition(0)
        engine_boots = security_param.getComponentByPosition(1)
        engine_time = security_param.getComponentByPosition(2)
        user_name = security_param.getComponentByPosition(3)
        digest = security_param.getComponentByPosition(4)
        priv_salt = security_param.getComponentByPosition(5)

        # Make sure we have the user in our database
        self._assert_user_in_database(user_name)

        # Authenticate the message
        if is_auth:
            auth_mod = self.get_v3_auth_module(user_name)
            auth_key = self.get_v3_auth_key(user_name, authoritative_engine_id)
            try:
                auth_mod.authenticateIncomingMsg(auth_key, digest, trap_data)
            except:
                # Authentication failed.
                reason = 'Invalid auth password for user %s' % user_name
                raise SNMPv3AuthenticationFailed(reason)
                # TODO: log this. maybe generate a notification.

        # Decrypt the message
        pdu = message.getComponentByPosition(3)
        if is_priv:
            pdu = pdu.getComponentByPosition(1)
        else:
            pdu = pdu.getComponentByPosition(0)
        priv_mod = self.get_v3_priv_module(user_name)
        priv_key = self.get_v3_priv_key(user_name, authoritative_engine_id)
        priv_param = (engine_boots, engine_time, priv_salt)
        pdu = priv_mod.decryptData(priv_key, priv_param, pdu)
        if is_priv:
            try:
                pdu = decoder.decode(pdu, asn1Spec=ScopedPDU())[0]
            except:
                reason = 'Invalid priv password for user %s' % user_name
                raise SNMPv3DecryptionFailed(reason)
        pdu = pdu.getComponentByPosition(2).getComponentByPosition(6)

        self.parse_snmpv2_pdu(api.v2c, pdu, host)


    def listen(self):
        logging.info('SNMPListener: Trying to listen UDP on port %s',\
                     str(self.port))
        try:
            reactor.listenUDP(self.port, SNMPDatagramProtocol(self))
            logging.info('SNMPListener: Listening on port %s', str(self.port))
        except:
            logging.error('SNMPListener: Failed to listen on port %s',\
                          str(self.port))


    def _assert_user_in_database(self, user_name):
        """ Tests if the user is in the database """
        if user_name not in self.users.keys():
            raise SNMPv3AuthenticationFailed('Missing user %s from database'\
                    % user_name)


    def get_v3_auth_module(self, user_name):
        """
        Returns the associated authentication module with the given
        user. Possible values: HmacMd5, HmacSha, NoAuth.
        """
        user_obj = self.users[user_name]

        # Return the appropiate auth module
        auth_mode = user_obj.auth_mode
        if auth_mode == SNMPv3User.hmac_md5_auth:
            return SNMPUtils.snmpv3_md5_auth
        if auth_mode == SNMPv3User.hmac_sha_auth:
            return SNMPUtils.snmpv3_sha_auth
        return SNMPUtils.snmpv3_no_auth


    def get_v3_auth_key(self, user_name, engine_id):
        """ Returns the authentication key associated with the given user """
        user_obj = self.users[user_name]
        return user_obj.get_auth_key(engine_id)


    def get_v3_priv_module(self, user_name):
        """
        Returns the associated encryption module with the given
        user. Possible values: Des, NoPriv.
        """
        user_obj = self.users[user_name]

        # Return the appropiate priv module
        priv_mode = user_obj.priv_mode
        if priv_mode == SNMPv3User.des_priv:
            return SNMPUtils.snmpv3_des_priv
        return SNMPUtils.snmpv3_no_priv


    def get_v3_priv_key(self, user_name, engine_id):
        """ Returns the private key associated with the given user """
        user_obj = self.users[user_name]
        return user_obj.get_priv_key(engine_id)


    def add_snmpv3_user(self, snmpv3_user):
        """ Adds a SNMPv3User to the database """

        # If the user_name already exists, return. XXX
        if snmpv3_user.user_name in self.users.keys():
            print '%s exists' % snmpv3_user.user_name
            return

        self.users[snmpv3_user.user_name] = snmpv3_user
        self.shell.database.insert(SNMPv3User.collection_name,\
                snmpv3_user.db_fields)



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



class SNMPUtils:

    # SNMPv3 authentication protocols
    snmpv3_md5_auth = auth.hmacmd5.HmacMd5()
    snmpv3_sha_auth = auth.hmacsha.HmacSha()
    snmpv3_no_auth = auth.noauth.NoAuth()

    # SNMPv3 encryption protocols
    snmpv3_des_priv = priv.des.Des()
    snmpv3_no_priv = priv.nopriv.NoPriv()


    @staticmethod
    def parse_description(variables_dict):
        description_str = 'Variable bindings:\n'
        for var_key in variables_dict:
            description_line = '\t %s = %s\n' % (str(var_key),\
                    str(variables_dict[var_key]))
            description_str += description_line

        return description_str.rstrip('\n')


    @staticmethod
    def parse_type(generic_trap_id):
        # Cold Start
        if generic_trap_id == 0:
            return NotificationTypes.info

        # Warm Start
        if generic_trap_id == 1:
            return NotificationTypes.recovery

        # Link Down
        if generic_trap_id == 2:
            return NotificationTypes.critical

        # Link Up
        if generic_trap_id == 3:
            return NotificationTypes.recovery

        # Authentication Failure
        if generic_trap_id == 4:
            return NotificationTypes.security_alert

        # EGP Neighbour Loss
        if generic_trap_id == 5:
            return NotificationTypes.warning

        # Enterprise specific
        return NotificationTypes.unknown


    @staticmethod
    def fill_fields_with_host_info(fields, host):
        # Determine if the IP Address is IPv4 or IPv6
        host_ip = str(host)
        is_ipv4 = True
        try:
            socket.inet_aton(host_ip)
        except:
            is_ipv4 = False

        # Initialisation of the IP address based on the previous logic
        fields[NotificationFields.source_host_ipv4] = ''
        fields[NotificationFields.source_host_ipv6] = ''
        if is_ipv4:
            fields[NotificationFields.source_host_ipv4] = host_ip
        else:
            fields[NotificationFields.source_host_ipv6] = host_ip

        fields[NotificationFields.hostname] = socket.gethostbyaddr(host_ip)[0]



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



class SNMPv1Notification(Notification):
    """ The notification class for SNMPv1 """

    @staticmethod
    def get_name():
        return 'SNMPv1Notification'

    @staticmethod
    def get_fields_class():
        return SNMPv1NotificationFields


class SNMPv1NotificationFields(NotificationFields):
    """ The fields associated with the SNMPv1Notification class """

    names = copy(NotificationFields.names)
    types = copy(NotificationFields.types)

    # Set the names
    generic_trap_id = 'snmp_v1_generic_trap_id'
    enterprise_trap_id = 'snmp_v1_enterprise_trap_id'
    uptime = 'snmp_v1_uptime'
    enterprise_oid = 'snmp_v1_enterprise_oid'
    names.append(generic_trap_id)
    names.append(enterprise_trap_id)
    names.append(uptime)
    names.append(enterprise_oid)

    # Set the types
    types[generic_trap_id] = int
    types[enterprise_trap_id] = int
    types[uptime] = int
    types[enterprise_oid] = str

    @staticmethod
    def get_names():
        return SNMPv1NotificationFields.names

    @staticmethod
    def get_types():
        return SNMPv1NotificationFields.types



class SNMPv2cNotification(Notification):
    """ The notification class for SNMPv2c """

    @staticmethod
    def get_name():
        return 'SNMPv2cNotification'

    @staticmethod
    def get_fields_class():
        return SNMPv2cNotificationFields


class SNMPv2cNotificationFields(NotificationFields):
    """ The fields associated with the SNMPv2cNotification class """

    names = copy(NotificationFields.names)
    types = copy(NotificationFields.types)

    # Set the names
    uptime = 'snmp_v2c_uptime'
    trap_oid = 'snmp_v2c_trap_oid'
    enterprise_oid = 'snmp_v2c_enterprise_oid'
    names.append(uptime)
    names.append(trap_oid)
    names.append(enterprise_oid)

    # Set the types
    types[uptime] = int
    types[trap_oid] = str
    types[enterprise_oid] = str

    @staticmethod
    def get_names():
        return SNMPv2cNotificationFields.names

    @staticmethod
    def get_types():
        return SNMPv2cNotificationFields.types



class SNMPv3User:
    """
    Class to define a SNMPv3 user.
    It's used to authenticate/decrypt a TRAP received from a device.
    """

    # The collection where these entries will be stored
    collection_name = 'snmpv3_usm_users'

    # Fields
    auth_mode = 'auth_mode'
    priv_mode = 'priv_mode'
    auth_pass = 'auth_pass'
    priv_pass = 'priv_pass'
    user_name = 'user_name'

    # Authentication mode values
    no_auth = 0
    hmac_md5_auth = 1
    hmac_sha_auth = 2

    # Privacy mode values
    no_priv = 0
    des_priv = 1


    def __init__(self, db_fields=None, user_name=None,\
            auth_mode=0, priv_mode=0, auth_pass='', priv_pass=''):
        """
        Constructs a SNMPv3User object from a db object.

        There are 2 initialisations modes:
        * When db_fields is the object extracted from the database and the
        object properties will be copied from this.
        * When db_fields is None and the information will be taken from the
        other parameters.
        """
        if db_fields is None and user_name is None:
            raise InvalidSNMPv3User('Invalid initialisation')

        if db_fields is not None:
            self._init_from_db(db_fields)
        else:
            self._init_from_param(user_name, auth_mode, priv_mode,\
                    auth_pass, priv_pass)

        if self.auth_mode == SNMPv3User.no_auth and\
                self.priv_mode != SNMPv3User.no_priv:
            raise InvalidSNMPv3User('Invalid NoAuthPriv security level')


    def _init_from_db(self, db_fields):
        # Inits the object from a database object.
        try:
            self.auth_mode = db_fields[SNMPv3User.auth_mode]
            self.priv_mode = db_fields[SNMPv3User.priv_mode]
            self.auth_pass = db_fields[SNMPv3User.auth_pass]
            self.priv_pass = db_fields[SNMPv3User.priv_pass]
            self.user_name = db_fields[SNMPv3User.user_name]
        except:
            raise InvalidSNMPv3User('Missing field in database ')

        # Save it to be used later if needed.
        self.db_fields = db_fields


    def _init_from_param(self, user_name, auth_mode, priv_mode,\
            auth_pass, priv_pass):
        # Inits the object from the given parameters
        if type(user_name) != str:
            raise InvalidSNMPv3User('The user name must be of type str')

        # The actual initialisations
        self.auth_mode = auth_mode
        self.priv_mode = priv_mode
        self.auth_pass = auth_pass
        self.priv_pass = priv_pass
        self.user_name = user_name

        # Save the db_fields to be used later if needed.
        self.db_fields = dict()
        self.db_fields[SNMPv3User.auth_mode] = self.auth_mode
        self.db_fields[SNMPv3User.priv_mode] = self.priv_mode
        self.db_fields[SNMPv3User.auth_pass] = self.auth_pass
        self.db_fields[SNMPv3User.priv_pass] = self.priv_pass
        self.db_fields[SNMPv3User.user_name] = self.user_name


    def get_priv_key(self, engine_id):
        """
        Returns the privacy key associated with this user.
        engine_id: The engine_id from which the TRAP originated.
        """
        if self.auth_mode == SNMPv3User.hmac_sha_auth:
            return localkey.passwordToKeySHA(self.priv_pass, engine_id)
        if self.auth_mode == SNMPv3User.hmac_md5_auth:
            return localkey.passwordToKeyMD5(self.priv_pass, engine_id)
        return None


    def get_auth_key(self, engine_id):
        """
        Returns the authentication key associated with this user.
        engine_id: The engine_id from which the TRAP originated.
        """
        if self.auth_mode == SNMPv3User.hmac_sha_auth:
            return localkey.passwordToKeySHA(self.auth_pass, engine_id)
        if self.auth_mode == SNMPv3User.hmac_md5_auth:
            return localkey.passwordToKeyMD5(self.auth_pass, engine_id)
        return None



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


class InvalidSNMPv3User(Exception):

    def __init__(self, reason):
        self.err_msg = reason

    def __str__(self):
        return repr(self.err_msg)


class SNMPv3AuthenticationFailed(Exception):

    def __init__(self, reason):
        self.err_msg = reason

    def __str__(self):
        return repr(self.err_msg)


class SNMPv3DecryptionFailed(Exception):

    def __init__(self, reason):
        self.err_msg = reason

    def __str__(self):
        return repr(self.err_msg)
