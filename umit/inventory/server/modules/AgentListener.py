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

from OpenSSL import crypto

from umit.inventory.server.Module import ListenerServerModule
from umit.inventory.server.Module import ServerModule
from umit.inventory.server.Notification import Notification
from umit.inventory.server.Notification import NotificationFields
from umit.inventory.common import AgentFields

from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import ssl
from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
from twisted.internet.address import IPv4Address

import socket
import logging
import json
import tempfile
from copy import copy
import os


class AgentListener(ListenerServerModule, ServerModule):

    # Options
    udp_port_option = 'listening_udp_port'
    ssl_port_option = 'listening_ssl_port'
    ssl_auth_enabled = 'ssl_authentication_enabled'

    # SSL expire: 10 years
    cert_expire = 316224000

    # SSL files
    cert_file_name = os.path.join(tempfile.gettempdir(), 'umit_agent.cert')
    key_file_name = os.path.join(tempfile.gettempdir(), 'umit_agent.key')


    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)

        self.udp_port = int(self.options[AgentListener.udp_port_option])
        self.ssl_port = int(self.options[AgentListener.ssl_port_option])
        self.ssl_auth = bool(self.options[AgentListener.ssl_auth_enabled])

        # Generate the SSL key and certificate
        logging.info('AgentListener: Loading SSL support ...')
        self.ssl_enabled = True
        try:
            self._generate_ssl_files()
        except:
            logging.error('AgentListener: Failed to load SSL support.',\
                          exc_info=True)
            self.ssl_enabled = False
        logging.info('AgentListener: Loaded SSL support')


    def _generate_ssl_files(self):
        # Certificate and key files only for this session
        key_file = open(self.key_file_name, 'w')
        cert_file = open(self.cert_file_name, 'w')

        # Generate the key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 1024)

        # Generate the certificate
        cert = crypto.X509()
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(AgentListener.cert_expire)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha1')

        # Write to files
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        key_file.close()
        cert_file.close()


    def get_name(self):
        return 'AgentListener'


    def get_protocol_name(self):
        return 'UmitAgent'


    def init_default_settings(self):
        self.options[AgentListener.udp_port_option] = '20000'
        self.options[AgentListener.ssl_port_option] = '20001'
        self.options[AgentListener.ssl_auth_enabled] = False


    def receive_message(self, host, port, data):
        try:
            temp = json.loads(data)
        except:
            logging.error('AgentListener: non-seriazable JSON notification.',\
                          exc_info=True)
            return

        # Must be careful, as it may be invalid and not contain all the fields.
        fields = dict()
        try:
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
    
            fields[NotificationFields.hostname] =\
                    str(temp[AgentFields.hostname])

            fields[NotificationFields.timestamp] =\
                    float(temp[AgentFields.timestamp])

            fields[NotificationFields.protocol] = str(self.get_protocol_name())

            fields[NotificationFields.notification_type] =\
                    str(temp[AgentFields.message_type])

            fields[NotificationFields.description] =\
                    unicode(temp[AgentFields.message])
            
            fields[AgentNotificationFields.monitoring_module] =\
                    unicode(temp[AgentFields.monitoring_module])

            for module_field in temp[AgentFields.module_fields].keys():
                fields[module_field] =\
                        temp[AgentFields.module_fields][module_field]
        except Exception, e:
            logging.error('AgentListener: Failed to get notification fields',\
                          exc_info=True)
            return

        try:
            notification = AgentNotification(fields)
            self.shell.parse_notification(self.get_name(), notification)
        except Exception, e:
            error_msg = 'AgentListener: Failed to convert notification to '
            error_msg += 'internal AgentNotification object.'
            logging.error(error_msg, exc_info=True)


    def listen(self):
        # Listen on UDP port
        logging.info('AgentListener: Trying to listen UDP on port %s',\
                     str(self.udp_port))
        try:
            reactor.listenUDP(self.udp_port, AgentDatagramProtocol(self))
            logging.info('AgentListener: Listening UDP on port %s',\
                         str(self.udp_port))
        except:
            logging.error('AgentListener: Failed to listen UDP on port %s',\
                          str(self.udp_port))

        # Listen on SSL port
        if not self.ssl_enabled:
            return
        ssl_factory = Factory()
        AgentSSLProtocol.agent_listener = self
        ssl_factory.protocol = AgentSSLProtocol
        ssl_context_factory = ssl.DefaultOpenSSLContextFactory(\
            self.key_file_name, self.cert_file_name)
        logging.info('AgentListener: Trying to listen SSL on port %s',\
                     str(self.ssl_port))
        try:
            reactor.listenSSL(self.ssl_port, ssl_factory, ssl_context_factory)
            logging.info('AgentListener: Listening SSL on port %s',\
                         str(self.ssl_port))
        except:
            logging.error('AgentListener: Failed to listen SSL on port %s',\
                          str(self.ssl_port))



class AgentDatagramProtocol(DatagramProtocol):
    """ The protocol used when receiving messages from the Agents on UDP """

    def __init__(self, agent_listener):
        self.agent_listener = agent_listener


    def datagramReceived(self, data, (host, port)):
        self.agent_listener.receive_message(host, port, data)



class AgentSSLProtocol(Protocol):
    """ The protocol used when receiving messages from the Agents on SSL """

    agent_listener = None

    def __init__(self):
        self.agent_listener = AgentSSLProtocol.agent_listener
        self.auth_enabled = self.agent_listener.ssl_auth
        self.shell = self.agent_listener.shell


    def dataReceived(self, data):
        peer = self.transport.getPeer()
        host = ''
        port = -1
        if isinstance(peer, IPv4Address):
            # TODO review this with support for IPv6
            host = peer.host
            port = peer.port
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
