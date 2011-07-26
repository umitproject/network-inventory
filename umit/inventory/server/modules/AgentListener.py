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
from umit.inventory.server.ServerInterface import ServerInterface
from umit.inventory.server.ServerInterfaceMessages import ResponseFields
from umit.inventory.server.Notification import Notification
from umit.inventory.server.Notification import NotificationFields
from umit.inventory.common import AgentFields
from umit.inventory.common import message_delimiter
from umit.inventory.common import AgentMessageTypes
from umit.inventory.common import NotificationTypes
from umit.inventory.common import keep_alive_timeout
from umit.inventory.common import AgentCommandFields
from umit.inventory.server.Host import Host

from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
import twisted.internet.ssl
from twisted.internet.protocol import Factory
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
import ssl


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

        self.agent_tracker = None
        self.command_tracker = None
        
        # Mapping request types to their handlers
        self.request_handlers = {\
            AgentRequestTypes.add_user : self.evaluate_add_user_request,\
            AgentRequestTypes.del_user : self.evaluate_del_user_request,\
            AgentRequestTypes.get_users : self.evaluate_get_users_request,\
            AgentRequestTypes.get_configs : self.evaluate_get_configs_request,\
            AgentRequestTypes.set_configs : self.evaluate_set_configs_request,\
            AgentRequestTypes.restart : self.evaluate_restart_request,\
            }

        Notification.register_class(AgentNotification)


    def activate(self):
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

        # The users used for authentication if enabled
        self.users = {}

        # The command ports of the hosts in the network. If the value is
        # None, then the host is down
        self.hosts_command_port = {}

        # Mapping GET_CONFIG requests to their data_connection
        self.get_configs_map = dict()


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
        self.command_tracker = AgentCommandTracker(self.agent_tracker)
        self.agent_tracker.start()

        # TODO: delete this after testing is done:
        self.add_user('guest', 'guest')


    def add_user(self, username, password):
        if username not in self.users.keys():
            user_pass = hashlib.md5(password).hexdigest()
            self.users[username] = user_pass
            self.shell.database.insert(AgentListener.collection_name,\
                {'username' : username, 'md5_pass' : user_pass})


    def del_user(self, username):
        if username not in self.users.keys():
            return
        del self.users[username]
        self.shell.database.remove(AgentListener.collection_name,\
            {'username' : username})
            

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


    def evaluate_request(self, request, data_connection):
        req_id = request.get_request_id()
    
        agent_request = AgentRequest(request)

        if not agent_request.sanity_check():
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        request_type = agent_request.get_type()
        try:
            self.request_handlers[request_type](agent_request, req_id,\
                                                data_connection)
        except:
            logging.warning('AgentListener: Invalid request type', exc_info=True)


    def evaluate_set_configs_request(self, agent_request, req_id,\
                                     data_connection):
        # Check the format is correct
        set_configs_request = AgentSetConfigsRequest(agent_request)
        if not set_configs_request.sanity_check():
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        # Make sure the agent tracker is up
        hostname = set_configs_request.get_hostname()
        if self.agent_tracker is None or self.command_tracker is None:
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        # Check the host is tracked
        if not self.agent_tracker.have_host(hostname):
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        # Try sending the command
        configs = set_configs_request.get_configs()
        
        command_sent = self.command_tracker.send_command(hostname,\
                'GENERAL', 'SET_CONFIGS', command_body=configs)
        if not command_sent:
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
        else:
            response = ServerInterface.build_accepted_response(req_id)
            data_connection.send_message(json.dumps(response), True)


    def evaluate_get_configs_request(self, agent_request, req_id,\
                                     data_connection):
        get_configs_request = AgentGetConfigsRequest(agent_request)
        # Check the format is correct
        if not get_configs_request.sanity_check():
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        # Make sure the agent tracker is up
        hostname = get_configs_request.get_hostname()
        if self.agent_tracker is None or self.command_tracker is None:
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        # Check the host is tracked
        if not self.agent_tracker.have_host(hostname):
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        command_id = self.command_tracker.send_command(hostname,\
                'GENERAL', 'GET_CONFIGS',\
                handler_function=self.get_configs_handler,\
                handler_user_data=req_id)

        # If we failed sending the command
        if command_id is -1:
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
        else:
            self.get_configs_map[command_id] = data_connection

        # If we get here, we are waiting for an response from the agent


    def evaluate_restart_request(self, agent_request, req_id, data_connection):
        # Check the format is correct
        restart_request = AgentRestartRequest(agent_request)
        if not restart_request.sanity_check():
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        # Make sure the agent tracker is up
        hostname = restart_request.get_hostname()
        if self.agent_tracker is None or self.command_tracker is None:
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        # Check the host is tracked
        if not self.agent_tracker.have_host(hostname):
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        # Try sending the command
        command_id = self.command_tracker.send_command(hostname,\
                'GENERAL', 'RESTART')
        if command_id is -1:
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
        else:
            response = ServerInterface.build_accepted_response(req_id)
            data_connection.send_message(json.dumps(response), True)


    def evaluate_add_user_request(self, agent_request, req_id, data_connection):
        add_user_request = AgentAddUserRequest(agent_request)
        if not add_user_request.sanity_check():
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        username = add_user_request.get_username()
        password = add_user_request.get_password()
        self.del_user(username)
        response = ServerInterface.build_accepted_response(req_id)
        data_connection.send_message(json.dumps(response), True)


    def evaluate_del_user_request(self, agent_request, req_id, data_connection):
        del_user_request = AgentDelUserRequest(agent_request)
        if not del_user_request.sanity_check():
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        username = del_user_request.get_username()
        self.del_user(username)
        response = ServerInterface.build_accepted_response(req_id)
        data_connection.send_message(json.dumps(response), True)


    def evaluate_get_users_request(self, agent_request, req_id, data_connection):
        usernames = self.users.keys()

        response = ServerInterface.build_accepted_response(req_id)
        body = dict()
        body[AgentGetUsersResponseBody.usernames] = usernames
        response[ResponseFields.body] = body
        data_connection.send_message(json.dumps(response), True)


    def get_configs_handler(self, message, command_id, user_data, closed=False):
        req_id = user_data
        data_connection = self.get_configs_map[command_id]

        if closed:
            err_msg = 'AgentListener: Failed GET_CONFIGS from agent.\n'
            err_msg += 'Connection closed by agent.'
            logging.warning(err_msg)
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        if command_id not in self.get_configs_map.keys():
            err_msg = 'AgentListener: GET_CONFIGS agent request with invalid id'
            logging.warning(err_msg)
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        configs = message
        response = ServerInterface.build_accepted_response(req_id)
        body = dict()
        body[AgentGetConfigsResponseBody.configs] = configs
        response[ResponseFields.body] = body
        data_connection.send_message(json.dumps(response), True)


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
        ssl_context_factory = twisted.internet.ssl.DefaultOpenSSLContextFactory(\
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


    def have_host(self, hostname):
        """ Returns True if the hostname is tracked, False otherwise """
        return hostname in self.agents_info.keys()


    def get_username(self, hostname):
        """ Returns the username used by an agent, or None if none is used """
        try:
            return self.agents_info[hostname].username
        except:
            return None


    def get_password(self, hostname):
        """ Returns the password used by an agent, or None if none is used """
        try:
            return self.agents_info[hostname].password
        except:
            return None


    def get_host_ipv4(self, hostname):
        """ Returns the IPv4 address of a host, or None if no such host """
        try:
            return self.agents_info[hostname].host.ipv4_addr
        except:
            return None


    def get_host_ipv6(self, hostname):
        """ Returns the IPv6 address of a host, or None if no such host """
        try:
            return self.agents_info[hostname].host.ipv6_addr
        except:
            return None


    def get_command_id(self, hostname):
        """
        Returns a new command id to be used for a command to the agent or None
        if the hostname isn't registered.
        """
        try:
            return self.agents_info[hostname].get_command_id()
        except:
            return None


    def get_command_port(self, hostname):
        """
        Returns the command port for an agent on a host or -1 if no such port.
        """
        try:
            return self.agents_info[hostname].command_port
        except:
            return -1


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

        # Update the authentication data
        try:
            username = message[AgentFields.username]
            password = message[AgentFields.password]
            self.agents_info[hostname].set_auth_info(username, password)
        except:
            self.agents_info[hostname].set_auth_info(None, None)
            

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
        self.last_command_id = 0

        self.username = None
        self.password = None


    def set_auth_info(self, username, password):
        self.username = username
        self.password = password


    def update_keep_alive(self):
        self.last_keep_alive = time.time()


    def get_command_id(self):
        self.last_command_id += 1
        return self.last_command_id



class AgentCommandTracker:

    def __init__(self, agent_tracker):
        self.agent_tracker = agent_tracker


    def send_command(self, hostname, target, command_name,\
                     command_body=dict(), handler_function=None,\
                     handler_user_data=None):
        """
        Send a command to an agent:
        target: The target of the command.
        command_name: The name of the command.
        command_body: The body of the command (if present)
        hostname: The hostname on which the agent is present.
        handler_function: function to be called when a response is received. It
        should have the definition handler_function(message, command_id,\
        handler_user_data, closed=False) and it should return True if more
        responses are accepted, False otherwise.

        Returns a positive integer representing the command id, or -1 on failure.
        """
        # Get the host information
        ip_addr = None
        ipv4 = self.agent_tracker.get_host_ipv4(hostname)
        if ipv4 not in ['', None]:
            ip_addr = ipv4
        ipv6 = self.agent_tracker.get_host_ipv6(hostname)
        if ip_addr is not None and ipv6 not in ['', None]:
            ip_addr = ipv6

        command_port = self.agent_tracker.get_command_port(hostname)

        if ip_addr is None or command_port is -1:
            return -1

        # Get a new command id
        command_id = self.agent_tracker.get_command_id(hostname)

        # Get the user information
        username = self.agent_tracker.get_username(hostname)
        password = self.agent_tracker.get_password(hostname)

        # Serialize the command
        command = AgentCommand.serialize_command(target, command_name,\
                command_id, username, password, command_body)

        # Send the command
        command_connection = AgentCommandConnection(ip_addr, command_port,\
                command_id, handler_function, handler_user_data)
        command_sent = command_connection.send_command(command)
        if not command_sent:
            return False

        # Listen for responses if a handler is given
        if handler_function is not None:
            command_connection.start()
        else:
            command_connection.shutdown()

        return True



class AgentCommandConnection(Thread):

    def __init__(self, ip, port, command_id, handler_function=None,\
                 handler_user_data=None):
        Thread.__init__(self)
        self.daemon = True

        self.peer_ip = ip
        self.peer_port = port
        self.command_id = command_id
        self.handler_function = handler_function
        self.handler_user_data = handler_user_data
        
        self.should_shutdown = True
        self.shutdown_lock = Lock()

        self.data_socket = None
        self.connected = False
        self.buffer = ''
        self._connect()


    def _connect(self):
        self.data_socket = socket.socket()
        self.data_socket = ssl.wrap_socket(self.data_socket)
        try:
            self.data_socket.connect((self.peer_ip, self.peer_port))
            self.connected = True
        except:
            err_msg = "AgentListener: Failed to connect for commands to %s:%s"
            logging.warning(err_msg, str(self.peer_ip), str(self.peer_port),\
                            exc_info=True)
            self.connected = False


    def _recv(self):
        chunk = []
        while message_delimiter not in chunk:
            try:
                chunk = self.data_socket.recv(4096)
            except:
                logging.error('Failed receiving command from %s:%s',\
                    str(self.peer_ip), str(self.peer_port))
                return None

            if chunk == '':
                return None
            self.buffer += chunk
        buffer_parts = self.buffer.split(message_delimiter)
        self.buffer = buffer_parts[1]
        logging.debug('Received message from %s:%s.\n%s',\
                      str(self.peer_ip), str(self.peer_port), buffer_parts[0])
        return self._parse_command(buffer[0])


    def _parse_command(self, serialized_command):
        # TODO - decide if more checking should be realized here
        try:
            command = json.loads(serialized_command)
            command_body = command[AgentFields.command_response_fields]
            return command_body
        except:
            return None


    def send_command(self, data):
        self.data_socket.setblocking(0)
        total_sent_b = 0
        data += message_delimiter
        length = len(data)

        try:
            while total_sent_b < length:
                sent = self.data_socket.send(data[total_sent_b:])
                if sent is 0:
                    logging.error('Failed sending command data from %s:%s',\
                                  str(self.peer_ip), str(self.peer_port))
                    self.data_socket.setblocking(1)
                    return False

                total_sent_b += sent
        except:
            logging.error('Failed sending command data from %s:%s',\
                          str(self.peer_ip), str(self.peer_port))

            self.data_socket.setblocking(1)
            return False

        self.data_socket.setblocking(1)
        return True


    def shutdown(self):
        self.shutdown_lock.acquire()
        self.should_shutdown = True
        try:
            self.data_socket.close()
        except:
            pass
        self.shutdown_lock.release()


    def run(self):
        if not self.connected:
            self.handler_function(None, self.command_id,\
                                  self.handler_user_data, closed=True)
            return

        while True:
            self.shutdown_lock.acquire()
            if self.should_shutdown:
                self.shutdown_lock.release()
                break
            self.shutdown_lock.release()
            
            message = self._recv()
            if message is None:
                self.handler_function(None, self.command_id,\
                                      self.handler_user_data, closed=True)
                self.shutdown()
                break
            if not self.handler_function(message, self.command_id,\
                                         self.handler_user_data):
                self.shutdown()
                break



class AgentRequest:

    def __init__(self, request):
        self.request = request

        self.type = None
        self.body = None


    def sanity_check(self):
        """ Checks the fields. Must be called after initialization """
        # Check the type
        try:
            self.type = self.request.body[AgentRequestBody.type]
        except:
            err_msg = 'ServerInterface: Missing type from agent request'
            logging.warning(err_msg)
            return False

        # Check the body (optional)
        if AgentRequestBody.body in self.request.body:
            self.body = self.request.body[AgentRequestBody.body]

        return True


    def get_type(self):
        return self.type


    def get_body(self):
        return self.body



class AgentGetConfigsRequest:

    def __init__(self, agent_request):
        self.body = agent_request.get_body()

        self.hostname = None


    def sanity_check(self):
        try:
            self.hostname = self.body[AgentGetConfigsRequestBody.hostname]
        except:
            err_msg = 'ServerInterface: Missing hostname field from'
            err_msg += ' agent GET_CONFIGS request'
            logging.warning(err_msg)
            return False

        return True


    def get_hostname(self):
        return self.hostname



class AgentSetConfigsRequest:

    def __init__(self, agent_request):
        self.body = agent_request.get_body()

        self.hostname = None
        self.configs = None

    def sanity_check(self):
        try:
            self.hostname = self.body[AgentSetConfigsRequestBody.hostname]
        except:
            err_msg = 'ServerInterface: Missing hostname field from'
            err_msg += ' agent SET_CONFIGS request'
            logging.warning(err_msg)
            return False

        try:
            self.configs = self.body[AgentSetConfigsRequestBody.configs]
        except:
            err_msg = 'ServerInterface: Missing configs field from'
            err_msg += ' agent SET_CONFIGS request'
            logging.warning(err_msg)
            return False

        return True


    def get_hostname(self):
        return self.hostname


    def get_configs(self):
        return self.configs



class AgentRestartRequest:

    def __init__(self, agent_request):
        self.body = agent_request.get_body()

        self.hostname = None


    def sanity_check(self):
        try:
            self.hostname = self.body[AgentRestartRequestBody.hostname]
        except:
            err_msg = 'ServerInterface: Missing hostname field from'
            err_msg += ' agent RESTART request'
            logging.warning(err_msg)
            return False

        return True


    def get_hostname(self):
        return self.hostname


class AgentAddUserRequest:

    def __init__(self, agent_request):
        self.body = agent_request.get_body()

        self.username = None
        self.password = None


    def sanity_check(self):
        try:
            self.username = self.body[AgentAddUserRequestBody.agent_username]
        except:
            err_msg = 'ServerInterface: Missing agent_username field from'
            err_msg += ' agent ADD_USER request'
            logging.warning(err_msg)
            return False

        try:
            self.password = self.body[AgentAddUserRequestBody.agent_password]
        except:
            err_msg = 'ServerInterface: Missing agent_password field from'
            err_msg += ' agent ADD_USER request'
            logging.warning(err_msg)
            return False
        
        return True


    def get_username(self):
        return self.username


    def get_password(self):
        return self.password



class AgentDelUserRequest:

    def __init__(self, agent_request):
        self.body = agent_request.get_body()

        self.username = None


    def sanity_check(self):
        try:
            self.username = self.body[AgentAddUserRequestBody.agent_username]
        except:
            err_msg = 'ServerInterface: Missing agent_username field from'
            err_msg += ' agent DEL_USER request'
            logging.warning(err_msg)
            return False

        return True


    def get_username(self):
        return self.username

    

class AgentRequestTypes:

    get_configs = "GET_CONFIGS"
    set_configs = "SET_CONFIGS"
    restart = "RESTART"
    add_user = "ADD_USER"
    del_user = "DEL_USER"
    get_users = "GET_USERS"


    
class AgentRequestBody:
    """
    The fields for a request sent to the AgentListener.
    * type: The type of the request. It can have one of the following values:
      - GET_CONFIGS: It requests the configurations of an agent.
      - SET_CONFIGS: It requests setting the configurations of an agent.
      - RESTART: An agent restart is requested.
      - ADD_USER: Adding a user (or modifying an existing password) is requested.
      - DEL_USER: Deleting a user is requested.
      - GET_USERS: It requests the users and their passwords.
    * body: The body of the request (if required).
    """
    type = 'agent_request_type'
    body = 'agent_request_body'


class AgentSetConfigsRequestBody:
    """
    The fields for a SET_CONFIGS request.
    * hostname: The hostname of the agent to be configured.
    * configs: The configurations to applied to the agent.
    """
    hostname = 'hostname'
    configs = 'configs'


class AgentGetConfigsRequestBody:
    """
    The fields for a GET_CONFIGS request.
    * hostname: The hostname of the agent from which to get the configurations.
    """
    hostname = 'hostname'


class AgentRestartRequestBody:
    """
    The fields for a RESTART request.
    * hostname: The hostname on which the agent should be restarted.
    """
    hostname = 'hostname'


class AgentAddUserRequestBody:
    """
    The fields for an ADD_USER request.
    * agent_username: The name of the user to be added.
    * agent_password: The associated password with the username.
    """
    agent_username = 'agent_username'
    agent_password = 'agent_password'


class AgentDelUserRequestBody:
    """
    The fields for an DEL_USER request.
    * agent_username: The name of the user to be deleted
    """
    agent_username = 'agent_username'


# Request responses formats

class AgentGetUsersResponseBody:
    """
    The response fields for a "GET_USERS" request.
    * usernames: A list with all the agent usernames.
    """
    usernames = 'usernames'


class AgentGetConfigsResponseBody:
    """
    The response fields for a "GET_CONFIGS" request.
    * configs: The configuration dictionary of the agent.
    """
    configs = 'configs'


# Agent commands serializer

class AgentCommand:

    @staticmethod
    def serialize_command(self, target, command_name, command_id,\
                          username=None, password=None, body=dict()):
        command = dict()
        command[AgentCommandFields.command] = command_name
        command[AgentCommandFields.command_id] = command_id
        command[AgentCommandFields.target] = target
        command[AgentCommandFields.body] = body
        if username is not None:
            command[AgentCommandFields.username] = username
            command[AgentCommandFields.password] = password

        return json.dumps(command)