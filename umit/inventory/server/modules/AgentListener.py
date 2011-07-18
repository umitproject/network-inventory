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
from umit.inventory.common import message_delimiter
from umit.inventory.common import AgentMessageTypes
from umit.inventory.common import NotificationTypes
from umit.inventory.common import keep_alive_timeout
from umit.inventory.server.Host import Host

from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import ssl
from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
from twisted.protocols.basic import LineReceiver
from twisted.internet.address import IPv4Address

import socket
import logging
import time
import json
import tempfile
from copy import copy
import os
import hashlib
from threading import Thread
from threading import Lock


class AgentListener(ListenerServerModule, ServerModule):

    # User System database collection name
    collection_name = 'agent_listener_users'

    # User System collection fields
    db_username = 'username'
    db_md5_pass = 'md5_pass'

    # Options
    udp_port_option = 'listening_udp_port'
    ssl_port_option = 'listening_ssl_port'
    ssl_auth_enabled = 'ssl_authentication_enabled'
    udp_auth_enabled = 'udp_authentication_enabled'

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
        self.udp_auth = bool(self.options[AgentListener.udp_auth_enabled])

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

        self.agent_tracker = None
        # The users used for authentication if enabled
        self.users = {}

        # The command ports of the hosts in the network. If the value is
        # None, then the host is down
        self.hosts_command_port = {}

        Notification.register_class(AgentNotification)


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


    def init_database_operations(self):
        # Construct the users dictionary with entries (username: md5_pass)
        # used to authenticate notifications if this is enabled.
        db_entries = self.shell.database.find(AgentListener.collection_name)
        for user_entry in db_entries:
            try:
                username = user_entry[AgentListener.db_username]
                md5_pass = user_entry[AgentListener.db_md5_pass]
            except:
                logging.error('Agent Listener: Invalid user entry in database.',\
                              exc_info=True)
                continue
            self.users[username] = md5_pass

        # Get the list of hosts from the database
        hosts_list = self.shell.database.get_hosts()
        self.agent_tracker = AgentTracker(self.shell, hosts_list)
        self.agent_tracker.start()

        # TODO: delete this after testing is done:
        if 'guest' not in self.users.keys():
            guest_pass = hashlib.md5('guest').hexdigest()
            self.users['guest'] = guest_pass
            self.shell.database.insert(AgentListener.collection_name,\
                {'username' : 'guest', 'md5_pass' : guest_pass})


    def init_default_settings(self):
        self.options[AgentListener.udp_port_option] = '20000'
        self.options[AgentListener.ssl_port_option] = '20001'
        self.options[AgentListener.ssl_auth_enabled] = True
        self.options[AgentListener.udp_auth_enabled] = False


    def receive_message(self, host, port, data, authenticate):
        try:
            temp = json.loads(data)
        except:
            logging.error('AgentListener: non-seriazable JSON notification.',\
                          exc_info=True)
            return

        # If we have authentication enabled, test it
        if authenticate and not self.authenticate_notification(temp):
            logging.warning('AgentListener: Authentication Failure from %s:%s',\
                            str(host), str(port))
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

            # Check if it's a KEEP_ALIVE or GOING_DOWN message
            message_type = str(temp[AgentFields.message_type])
            if message_type == AgentMessageTypes.keep_alive or\
               message_type == AgentMessageTypes.going_down:
                if is_ipv4:
                    self.agent_tracker.add_message((temp, host, ''))
                else:
                    self.agent_tracker.add_message((temp, '', host))
                return

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

            fields[NotificationFields.short_description] =\
                    unicode(temp[AgentFields.short_message])

            fields[NotificationFields.description] =\
                    unicode(temp[AgentFields.message])

            fields[NotificationFields.is_report] =\
                    bool(temp[AgentFields.is_report])
            
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


    def authenticate_notification(self, notification):
        # Get the username and password from the notification

        # Make sure it has the fields
        try:
            username = notification[AgentFields.username]
            password = notification[AgentFields.password]
        except:
            err_msg = 'AgentListener: Authentication Error. Received '
            err_msg += 'notification missing username, password or both'
            logging.error(err_msg, exc_info=True)
            return False

        # Compute the password digest
        md5_pass = hashlib.md5(password).hexdigest()

        # Verify we have the user in the database
        if not username in self.users.keys():
            err_msg = 'AgentListener: Authentication Error. Received '
            err_msg += 'notification from user %s, but user is missing'
            err_msg += ' from database'
            logging.error(err_msg, username)
            return False

        # Verify the password is correct
        if md5_pass != self.users[username]:
            err_msg = 'AgentListener: Authentication Error. Received '
            err_msg += 'notification from user %s, but password is invalid'
            logging.error(err_msg, username)
            return False

        logging.debug('AgentListener: Authentication successful from %s',
                      notification[NotificationFields.hostname])
        return True


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

        # Make sure we have enabled SSL
        if not self.ssl_enabled:
            return

        # Listen on SSL port
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
        self.agent_listener.receive_message(host, port, data,\
                                            self.agent_listener.udp_auth)



class AgentSSLProtocol(LineReceiver):
    """ The protocol used when receiving messages from the Agents on SSL """

    agent_listener = None

    def __init__(self):
        self.agent_listener = AgentSSLProtocol.agent_listener
        self.auth_enabled = self.agent_listener.ssl_auth
        self.shell = self.agent_listener.shell
        self.delimiter = message_delimiter


    def lineReceived(self, line):
        peer = self.transport.getPeer()
        host = ''
        port = -1
        if isinstance(peer, IPv4Address):
            # TODO review this with support for IPv6 (Twisted support?)
            host = peer.host
            port = peer.port
        self.agent_listener.receive_message(host, port, line,\
                                            self.auth_enabled)
        self.transport.loseConnection()



class AgentNotification(Notification):
    """ The notification class associated to this protocol """

    @staticmethod
    def get_name():
        return 'AgentNotification'

    @staticmethod
    def get_fields_class():
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



class AgentTracker(Thread):

    def __init__(self, shell, hosts):
        Thread.__init__(self)
        self.daemon = True

        self.shell = shell

        # hostname : AgentInformation
        self.agents_info = dict()
        for host in hosts:
            self.agents_info[host.hostname] = AgentInformation(host)

        self.received_messages = []
        self.received_messages_lock = Lock()

        self.should_shutdown = False
        self.should_shutdown_lock = Lock()


    def add_message(self, message):
        """ message must be a tuple (agent message, ipv4_addr, ipv6_addr) """
        self.received_messages_lock.acquire()
        self.received_messages.append(message)
        self.received_messages_lock.release()


    def _handle_messages(self):
        self.received_messages_lock.acquire()
        current_messages = self.received_messages
        self.received_messages = list()
        self.received_messages_lock.release()

        for message in current_messages:
            self._handle_message(message[0], message[1], message[2])


    def _handle_message(self, message, ipv4_addr='', ipv6_addr=''):
        logging.debug('AgentTracker: Handling notification:\n%s',\
                      str(message))
        try:
            message_type = message[AgentFields.message_type]
            hostname = message[AgentFields.hostname]
            timestamp = float(message[AgentFields.timestamp])
        except:
            logging.debug('AgentTracker: Failed handling notification',\
                          exc_info=True)
            return

        if message_type == AgentMessageTypes.keep_alive:
            command_port = int(message[AgentFields.command_port])
            if hostname not in self.agents_info.keys():
                host = Host(hostname, ipv4_addr, ipv6_addr)
                self.agents_info[hostname] = AgentInformation(host,\
                        command_port, time.time())
                self.shell.database.add_host(host)
                self._raise_recovery_notification(hostname, timestamp,\
                                                  ipv4_addr, ipv6_addr)
            else:
                self.agents_info[hostname].update_keep_alive()
                if self.agents_info[hostname].command_port == -1:
                    self.agents_info[hostname].command_port = command_port
                    self._raise_recovery_notification(hostname, timestamp,\
                                                      ipv4_addr, ipv6_addr)

        if message_type == AgentMessageTypes.going_down:
            description = 'Received GOING_DOWN message from host %s\n' % hostname
            description += 'The Umit Agent Daemon quit gracefully at %s.\n'\
                    % time.ctime(timestamp)
            short_description = 'Umit Agent going down'
            notif_type = NotificationTypes.warning
            self.shell.raise_notification(description, short_description,\
                    notif_type, False, ipv4_addr, ipv6_addr, hostname)


    def _raise_recovery_notification(self, hostname, timestamp,\
                                     ipv4_addr, ipv6_addr):
        description = 'Received first KEEP_ALIVE message from host %s\n'\
                        % hostname
        description += 'The Umit Agent Daemon on this machine is UP.'
        short_description = 'Umit Agent is UP.'
        notif_type = NotificationTypes.recovery
        self.shell.raise_notification(description, short_description,\
                    notif_type, False, ipv4_addr, ipv6_addr, hostname)
        

    def shutdown(self):
        self.should_shutdown_lock.acquire()
        self.should_shutdown = True
        self.should_shutdown_lock.release()


    def _test_agents_information(self):
        for agent_info in self.agents_info.values():
            # The host is already marked as down
            if agent_info.command_port == -1:
                continue

            # The timeout expired
            if agent_info.last_keep_alive + 3 * keep_alive_timeout < time.time():
                description = 'Haven\'t received a KEEP-ALIVE message from '
                description += 'the Umit Agent on %s in %.1f seconds\n' %\
                        (agent_info.host.hostname, 3 * keep_alive_timeout)
                description += 'Considering the Umit Agent daemon went down.\n'
                short_description = 'Umit Agent going down'
                notif_type = NotificationTypes.critical
                self.shell.raise_notification(description, short_description,\
                        notif_type, False, agent_info.host.ipv4_addr,\
                        agent_info.host.ipv6_addr, agent_info.host.hostname)
                agent_info.command_port = -1
                agent_info.last_keep_alive = -1


    def run(self):
        while True:
            self.should_shutdown_lock.acquire()
            if self.should_shutdown:
                self.should_shutdown_lock.release()
                break
            self.should_shutdown_lock.release()

            self._handle_messages()

            # Check if any host went down without sending a KEEP-ALIVE
            # message
            self._test_agents_information()

            time.sleep(2.0)



class AgentInformation:

    def __init__(self, host, command_port=-1, last_keep_alive=-1):
        """
        self.host: A Host object where the Agent is installed.
        self.command_port: The port on which the agent is listening for
        commands.
        self.last_keep_alive: The last time when a keep alive was received
        from this agent.
        """
        self.host = host
        self.command_port = command_port
        self.last_keep_alive = last_keep_alive


    def update_keep_alive(self):
        self.last_keep_alive = time.time()