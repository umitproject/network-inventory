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

from umit.inventory.server.Notification import NotificationFields
from umit.inventory.server.Database import Database
from umit.inventory.server.Configs import ServerConfig
from umit.inventory.common import message_delimiter
from umit.inventory.server.Module import ListenerServerModule

from umit.inventory.server.ServerInterfaceMessages import *



from twisted.internet import reactor
from twisted.internet.protocol import Factory
from twisted.internet.address import IPv4Address
from twisted.protocols.basic import LineReceiver
import twisted.internet.ssl

import socket
import logging
import ssl
import json
import tempfile
import time
import os
import string
from random import choice
from threading import Thread
from threading import Lock
from collections import deque


class ServerInterface:
    """ Provides an interface to access the local data to GUI applications """

    # SSL certificate expiration: 10 years
    cert_expire = 316224000

    # Token size for CONNECT requests
    token_size = 1024

    # SSL files
    cert_file_name = os.path.join(tempfile.gettempdir(),\
                                  'umit_server_interface.cert')
    key_file_name = os.path.join(tempfile.gettempdir(),\
                                 'umit_server_interface.key')


    def __init__(self, conf, user_system, shell):
        self.user_system = user_system
        self.conf = conf
        self.shell = shell
        self.requests_port =\
            int(self.conf.get_general_option(ServerConfig.interface_port))
        self.force_interface_encrypt =\
            bool(self.conf.get_general_option(ServerConfig.force_interface_encrypt))

        self._generate_ssl_files()

        # Get the name of the protocols which are listening on the server
        # and are enabled.
        modules = self.shell.get_modules_list()
        self.protocols = []
        for module in modules:
            if isinstance(module, ListenerServerModule):
                self.protocols.append(module.get_protocol_name())

        ServerInterfaceSSLProtocol.server_interface = self

        # Dictionary mapping request types to their evaluating functions
        self.request_eval_func = {\
            'SUBSCRIBE' : self.evaluate_subscribe_request,\
            'UNSUBSCRIBE' : self.evaluate_unsubscribe_request,\
            'GET_MODULES' : self.evaluate_get_modules_request,\
            'GET_HOSTS' : self.evaluate_get_hosts_request,\
            'GET_CONFIGS' : self.evaluate_get_configs_request,\
            'SET_CONFIGS' : self.evaluate_set_configs_request,\
            'RESTART' : self.evaluate_restart_request,\
            'SEARCH' : self.evaluate_search_request,\
            'SEARCH_NEXT' : self.evaluate_search_next_request,\
            'SEARCH_STOP' : self.evaluate_search_stop_request,\
            'ADD_USER' : self.evaluate_add_user_request,\
            'DEL_USER' : self.evaluate_del_user_request,\
            'SET_USER' : self.evaluate_set_user_request,\
            'GET_USERS' : self.evaluate_get_users_request\
            }

        # Dictionary mapping users to connections
        self.users_connections = {}

        # Users which are subscribed to notifications.
        # username : SubscribedUserContext
        self.subscribed_users = {}

        # Contexes used for searching
        self.search_contexes = {}


    @staticmethod
    def generate_token():
        token = ''
        for i in range(ServerInterface.token_size):
            token += choice(string.digits + string.ascii_letters +\
                            string.punctuation)
        return token


    @staticmethod
    def build_auth_denied_response(req_id):
        response = dict()
        response[ResponseFields.request_id] = req_id
        response[ResponseFields.response_code] = ResponseCodes.auth_denied
        return response


    @staticmethod
    def build_missing_connection_response(req_id):
        response = dict()
        response[ResponseFields.request_id] = req_id
        response[ResponseFields.response_code] = ResponseCodes.missing_connection
        return response


    @staticmethod
    def build_invalid_response(req_id):
        response = dict()
        response[ResponseFields.request_id] = req_id
        response[ResponseFields.response_code] = ResponseCodes.invalid
        return response


    @staticmethod
    def build_missing_permissions_response(req_id):
        response = dict()
        response[ResponseFields.request_id] = req_id
        response[ResponseFields.response_code] = ResponseCodes.missing_permissions
        return response

    @staticmethod
    def build_internal_error_response(req_id):
        response = dict()
        response[ResponseFields.request_id] = req_id
        response[ResponseFields.response_code] = ResponseCodes.internal_error
        return response

    
    @staticmethod
    def build_accepted_response(req_id):
        response = dict()
        response[ResponseFields.request_id] = req_id
        response[ResponseFields.response_code] = ResponseCodes.accepted
        return response


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
        cert.gmtime_adj_notAfter(ServerInterface.cert_expire)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha1')

        # Write to files
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        key_file.close()
        cert_file.close()


    def forward_notification(self, notification):
        """ Called when the Server receives a notification """
        msg = self.build_accepted_response(-1)
        msg[ResponseFields.response_type] = 'SUBSCRIBE_RESPONSE'
        msg[ResponseFields.body] = notification.fields
        msg = json.dumps(msg)

        for username in self.subscribed_users.keys():
            user_connection = self.users_connections[username]

            # If the connection died, remove it
            if user_connection.shutdown:
                del self.subscribed_users[username]
                del self.users_connections[username]
                continue
            # If we should send it in this context
            user_context = self.subscribed_users[username]
            if not user_context.should_send_notification(notification):
                continue
            # Forward the notification (if not a report) to the user
            if notification.fields[NotificationFields.is_report] is False:
                user_connection.send_message(msg)

        
    def get_connection(self, username):
        """
        Gets the connection for this request, or None if an 'CONNECT'
        request was not sent prior to this one.
        """
        if username in self.users_connections.keys():
            return self.users_connections[username]
        return None


    def evaluate_connect_request(self, username, encrypt_enabled, req_id):
        # If we already have a connection opened for this user, close it
        if username in self.users_connections.keys():
            self.users_connections[username].close_connection()
        user = self.user_system.get_user(username)

        token = self.generate_token()
                
        connection = InterfaceDataConnection(token, username, encrypt_enabled)
        self.users_connections[username] = connection
        connection.start()

        # Build the response
        response = self.build_accepted_response(req_id)
        connect_body = dict()
        connect_body[ConnectResponseBody.token] = token
        connect_body[ConnectResponseBody.encryption_enabled] =\
                encrypt_enabled or self.force_interface_encrypt
        connect_body[ConnectResponseBody.data_port] = connection.get_port()
        connect_body[ConnectResponseBody.permissions] =\
            user.permissions.serialize()
        connect_body[ConnectResponseBody.protocols] = self.protocols
        response[ResponseFields.body] = connect_body

        return str(json.dumps(response))


    def evaluate_subscribe_request(self, request, connection):
        username = request.get_username()
        user = self.user_system.get_user(username)
        req_id = request.get_request_id()

        general_request = GeneralRequest(request)
        if not general_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        subscribe_request = SubscribeGeneralRequest(general_request)
        if not subscribe_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        types = subscribe_request.get_types()
        hosts = subscribe_request.get_hosts()
        protocol = subscribe_request.get_protocol()

        self.subscribed_users[username] = SubscribedUserContext(user,\
                protocol, types, hosts)
        ok_response = self.build_accepted_response(req_id)
        connection.send_message(json.dumps(ok_response), True)


    def evaluate_unsubscribe_request(self, request, connection):
        username = request.get_username()
        req_id = request.get_request_id()
        if username in self.subscribed_users.keys():
            del self.subscribed_users[username]

        ok_response = self.build_accepted_response(req_id)
        connection.send_message(json.dumps(ok_response), True)


    def evaluate_get_modules_request(self, request, connection):
        username = request.get_username()
        req_id = request.get_request_id()

        response = self.build_accepted_response(req_id)
        get_modules_body = dict()
        get_modules_body[GetModulesResponseBody.modules] =\
                self.shell.get_modules_names_list()
        response[ResponseFields.body] = get_modules_body
        connection.send_message(json.dumps(response), True)


    def evaluate_get_hosts_request(self, request, connection):
        req_id = request.get_request_id()

        # Get the hosts from the database
        hosts = self.shell.database.get_hosts()
        hostnames = []
        ipv4_addresses = []
        ipv6_addresses = []
        for host in hosts:
            hostnames.append(host.hostname)
            ipv4_addresses.append(host.ipv4_addr)
            ipv6_addresses.append(host.ipv6_addr)

        # TODO - check hosts permissions here
        response = self.build_accepted_response(req_id)
        get_hosts_body = dict()
        get_hosts_body[GetHostsResponseBody.hostnames] = hostnames
        get_hosts_body[GetHostsResponseBody.ipv4_addresses] = ipv4_addresses
        get_hosts_body[GetHostsResponseBody.ipv6_addresses] = ipv6_addresses
        response[ResponseFields.body] = get_hosts_body
        connection.send_message(json.dumps(response), True)


    def evaluate_get_configs_request(self, request, connection):
        req_id = request.get_request_id()

        # Get the configurations
        configs = dict()
        sections = self.conf.sections()
        for section in sections:
            configs[section] = dict()
            options = self.conf.options(section)
            for option in options:
                configs[section][option] = self.conf.get(section, option)

        # TODO - check permissions here
        response = self.build_accepted_response(req_id)
        get_conf_body = dict()
        get_conf_body[GetConfigsResponseBody.configs] = configs
        response[ResponseFields.body] = get_conf_body
        connection.send_message(json.dumps(response), True)



    def evaluate_set_configs_request(self, request, connection):
        req_id = request.get_request_id()

        general_request = GeneralRequest(request)
        if not general_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        set_configs_request = SetConfigsGeneralRequest(general_request)
        if not set_configs_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        # TODO - check permissions

        self.shell.update_configs(set_configs_request.get_configs())
        response = self.build_accepted_response(req_id)
        connection.send_message(json.dumps(response), True)


    def evaluate_restart_request(self, request, connection):
        #TODO
        pass


    def evaluate_search_request(self, request, connection):
        username = request.get_username()
        req_id = request.get_request_id()

        general_request = GeneralRequest(request)
        if not general_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        search_request = SearchGeneralRequest(general_request)
        if not search_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        spec = search_request.get_spec()
        sort = search_request.get_sort()
        fields = search_request.get_fields()

        search_context = SearchContext.get_context(username,\
                database=self.shell.database)
        results = search_context.search(spec, sort, fields)

        if results is None:
            response = self.build_invalid_response(req_id)
        else:
            count = search_context.get_count()
            search_id = search_context.get_id()
            search_body = dict()
            search_body[SearchResponseBody.search_id] = search_id
            search_body[SearchResponseBody.results] = results
            search_body[SearchResponseBody.total_results_count] = count
            response = self.build_accepted_response(req_id)
            response[ResponseFields.body] = search_body

        connection.send_message(json.dumps(response), True)


    def evaluate_search_next_request(self, request, connection):
        username = request.get_username()
        req_id = request.get_request_id()

        general_request = GeneralRequest(request)
        if not general_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        search_request = SearchNextGeneralRequest(general_request)
        if not search_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        search_id = search_request.get_search_id()
        search_context = SearchContext.get_context(username, search_id)
        if search_context is None:
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        results = search_context.search_next(search_request.get_start_index())
        if results is None:
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        count = search_context.get_count()
        search_id = search_context.get_id()
        search_body = dict()
        search_body[SearchResponseBody.search_id] = search_id
        search_body[SearchResponseBody.results] = results
        search_body[SearchResponseBody.total_results_count] = count
        response = self.build_accepted_response(req_id)
        response[ResponseFields.body] = search_body

        connection.send_message(json.dumps(response), True)


    def evaluate_search_stop_request(self, request, connection):
        username = request.get_username()
        req_id = request.get_request_id()

        general_request = GeneralRequest(request)
        if not general_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        search_request = SearchStopGeneralRequest(general_request)
        if not search_request.sanity_check():
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        search_id = search_request.get_search_id()
        search_context = SearchContext.get_context(username, search_id)
        if search_context is None:
            response = self.build_invalid_response(req_id)
            connection.send_message(json.dumps(response), True)
            return

        search_context.search_stop()


        response = self.build_accepted_response(req_id)

        connection.send_message(json.dumps(response), True)


    def evaluate_add_user_request(self, request, connection):
        username = request.get_username()
        req_id = request.get_request_id()

        user = self.user_system.get_user(username)
        if not user.can_manage_users():
            connection.send_message(\
                self.build_missing_permissions_response(req_id))
            return

        # TODO

    def evaluate_del_user_request(self, request, connection):
        pass


    def evaluate_set_user_request(self, request, connection):
        pass


    def evaluate_get_users_request(self, request, connection):
        pass


    def evaluate_general_request(self, request, host, port):
        general_request = GeneralRequest(request)
        general_request_ok = general_request.sanity_check()
        if not general_request_ok:
            return

        general_request_type = general_request.get_type()
        request_id = request.get_request_id()
        username = request.get_username()

        if general_request_type == 'CONNECT':
            # Initialise the data connection for this user
            connect_general_request = ConnectGeneralRequest(general_request)

            connect_general_request_ok = connect_general_request.sanity_check()
            if not connect_general_request_ok:
                return None

            return self.evaluate_connect_request(username,\
                            connect_general_request.get_encryption_enabled(),\
                            request_id)
        else:
            # Get the connection for this user
            connection = self.get_connection(username)
            if connection is None:
                err_msg = 'ServerInterface: Received request prior to an '
                err_msg += 'CONNECT request from %s:%s'
                logging.error(err_msg, str(host), str(port))
                return None

            # Test if the connection died with the client
            if connection.shutdown:
                del self.users_connections[username]
                if username in self.subscribed_users:
                    self.subscribed_users.remove(username)
                return None

            # Run the evaluation function for this request
            self.request_eval_func[general_request_type](request, connection)

        return None


    def receive_request(self, data, host, port):
        """ Called when a request is received """

        request = Request(data, host, port)
        request_ok = request.sanity_check()

        if not request_ok:
            return None

        # Authenticate the request
        username = request.get_username()
        password = request.get_password()

        try:
            self.user_system.validate_user(username, password)
        except:
            logging.error('ServerInterface: Authentication failure from %s:%s',\
                          str(host), str(port), exc_info=True)
            return None

        # Check the target of the request
        target = request.get_target()
        if target == "GENERAL":
            # General request
            return self.evaluate_general_request(request, host, port)
        else:
            # Module specific request

            # Get the connection for this request
            username = request.get_username()
            connection = self.get_connection(username)
            if connection is None:
                err_msg = 'ServerInterface: Received request prior to an '
                err_msg += 'CONNECT request from %s:%s'
                logging.error(err_msg, str(host), str(port))
                return None

            # Check if the targeted module exists
            modules_names = self.shell.get_modules_names_list()
            if target not in modules_names:
                err_msg = 'ServerInterface: Invalid Request target %s from '
                err_msg += '%s:%s' % (str(host), str(port))
                logging.error(err_msg)
                return None

            # Forward the request to the module
            module = self.shell.get_module(target)
            module.evaluate_request(request, connection)

        return None


    def listen(self):
        """ Called when we should start listening to requests """
        ssl_factory = Factory()
        ServerInterfaceSSLProtocol.agent_listener = self
        ssl_factory.protocol = ServerInterfaceSSLProtocol
        ssl_context_factory = twisted.internet.ssl.DefaultOpenSSLContextFactory(\
            self.key_file_name, self.cert_file_name)
        logging.info('ServerInterface: Trying to listen SSL on port %s',\
                     str(self.requests_port))
        try:
            reactor.listenSSL(self.requests_port, ssl_factory, ssl_context_factory)
            logging.info('ServerInterface: Listening SSL on port %s',\
                         str(self.requests_port))
        except:
            logging.error('ServerInterface: Failed to listen SSL on port %s',\
                          str(self.requests_port), exc_info=True)



class SubscribedUserContext:
    """
    One object of this type will exist for each subscribed user.
    It describes which notifications should be sent for that user.
    """

    def __init__(self, user, protocol, types, hosts):
        """
        user: A User object for this context.
        protocols: A string describing for which protocol the notifications
        should be sent (or 'All' for all protocols).
        types: A list of types for which the notifications should be forwarded
        (or [] for all types).
        hosts: A list of hosts for which the notifications should be forwarded
        (or [] for all hosts).
        """
        self.user = user
        self.protocol = protocol
        self.all_protocols = (self.protocol == 'All')
        self.types = types
        self.all_types = (self.types == [])
        self.hosts = hosts
        self.all_hosts = (self.hosts == [])


    def should_send_notification(self, notification):
        if not self.all_protocols:
            notification_protocol =\
                    notification.fields[NotificationFields.protocol]
            if notification_protocol != self.protocol:
                return False

        if not self.all_types:
            notification_type =\
                    notification.fields[NotificationFields.notification_type]
            if notification_type not in self.types:
                return False

        if not self.all_hosts:
            hostname = notification.fields[NotificationFields.hostname]
            ipv4_addr = notification.fields[NotificationFields.source_host_ipv4]
            ipv6_addr = notification.fields[NotificationFields.source_host_ipv6]

            if hostname not in self.hosts and ipv4_addr not in self.hosts and\
                ipv6_addr not in self.hosts:
                return False

        # TODO test permissions
        return True



class SearchContext:
    """
    An object describing an user search. The object is alive until the
    user sends a SEARCH_STOP request.
    """
    page_size = 20

    # Used to get a new search id
    search_ids = {}

    # Used to get the current current valid search contexts
    search_contexts = {}


    @staticmethod
    def get_context(username, search_id=None, database=None):
        """
        Gets a SearchContext.
        username: The username for which the context should be returned.
        req_id: If None, a new search context will be returned. Else, it
        should be a valid search id.
        database: A Database object. It must be given if search_id is None.

        Returns: A SearchContext for this search or None if the parameters
        were invalid.
        """
        # A new Search Context
        if search_id is None:
            if not isinstance(database, Database):
                return None
            return SearchContext(username, database)

        # Getting an existing valid Search Context
        search_context_key = SearchContext._compute_key(username, search_id)
        if search_context_key in SearchContext.search_contexts.keys():
            return SearchContext.search_contexts[search_context_key]

        # Invalid Search Context
        return None


    @staticmethod
    def _compute_key(username, search_id):
        return str(username) + str(search_id)


    def __init__(self, username, database):
        """ Should not be used directly. Use get_context() """
        self.username = username
        self.database = database

        # Generate the search id - unique for each user
        if username not in self.search_ids.keys():
            self.search_ids[username] = 0
        else:
            self.search_ids[username] += 1
        self.search_id = self.search_ids[username]

        # Save the search context
        self_key = self._compute_key(username, self.search_id)
        SearchContext.search_contexts[self_key] = self

        self.spec = None
        self.sort = None
        self.fields = None

        self.cursor = None
        self.cursor_count = 0


    def get_id(self):
        return self.search_id


    def get_count(self):
        if self.cursor is None:
            return 0
        return self.cursor_count


    def search(self, spec, sort, fields):
        self.fields = fields
        self.spec = spec
        self.sort = sort
    
        try:
            collection_name = self.database.get_notifications_collection_name()
            self.cursor = self.database.find(collection_name,
                                             search_spec=self.spec,
                                             sorted_fields=self.sort,\
                                             returned_fields=self.fields,
                                             tailable=False)
            self.cursor_count = self.cursor.count()
        except:
            logging.debug('ServerInterface: Invalid search request.',\
                          exc_info=True)

        return self.search_next(0)


    def search_next(self, start_index):
        if self.cursor is None:
            return None

        if start_index >= self.cursor_count:
            return []

        end_index = min(self.cursor_count, start_index + self.page_size)
        results = []
        for index in range(start_index, end_index):
            result = self.cursor[index]
            # Clean the fields that are not JSON seriazable
            results.append(self.clean_db_result(result))

        return results


    @staticmethod
    def clean_db_result(db_result):
        """ Cleans the DB result so it's JSON seriazable """
        new_fields = dict()
        for field_key in db_result.keys():
            try:
                json.dumps(db_result[field_key])
                json.dumps(field_key)
                new_fields[field_key] = db_result[field_key]
            except:
                continue
        return new_fields


    def search_stop(self):
        search_context_key = self._compute_key(self.username, self.search_id)
        del self.search_contexts[search_context_key]



class ServerInterfaceSSLProtocol(LineReceiver):
    """ Listening for requests """

    # The ServerInterface object
    server_interface = None

    def __init__(self):
        self.server_interface = ServerInterfaceSSLProtocol.server_interface
        self.delimiter = message_delimiter


    def lineReceived(self, line):
        peer = self.transport.getPeer()
        host = ''
        port = -1
        if isinstance(peer, IPv4Address):
            # TODO IPv6?
            host = peer.host
            port = peer.port

        # The response is useful only for an AUTHENTICATE request
        response = self.server_interface.receive_request(line, host, port)

        if response is not None:
            self.sendLine(response)

        # Force closing the connection
        self.transport.loseConnection()



class InterfaceDataConnection(Thread):
    """
    Connection where all the responses (except the CONNECT response) will be
    sent. It uses a timeout and a message queue to avoid too many messages
    sent.
    """

    timeout = 10.0
    max_messages = 2

    min_port_value = 10001
    max_port_value = 30000

    max_failed_tokens = 5


    def __init__(self, token, username, encrypt_enabled=True):
        """
        token: The Connection first expects a token from the other side to make
        sure it's the authenticated user.
        username: Username owning the connection.
        encrypt_enabled: If the data port should be encrypted.
        """
        Thread.__init__(self)
        self.token = token
        self.daemon = True
        self.username = username

        # This will be True when the connection is no longer valid
        self.shutdown = False

        self.encrypt_enabled = encrypt_enabled

        self.message_queue = deque()
        self.message_queue_lock = Lock()
        self.last_sent_time = time.time()

        self.connected = False
        self.port = None

        self.token_socket = None
        self._listen()

        self.data_socket = None
        self.data_socket_lock = Lock()
        self.peer_host = None
        self.peer_port = None


    def _listen(self):
        """ Starts listening for connect requests """
        self.token_socket = socket.socket()

        for port in range(self.min_port_value, self.max_port_value):
            try:
                self.token_socket.bind(('0.0.0.0', port))
            except:
                continue
            self.port = port
            break

        if self.port is None:
            err_msg = 'ServerInterface: Couldn\'t find open port for data'
            err_msg += ' connection'
            logging.error(err_msg)
            self.shutdown = True
            return

        logging.info('ServerInterface: Listening for connections on port %d',\
                     self.port)
        self.token_socket.listen(1)


    def _connect(self):
        """ Connects and checks the token """

        if self.shutdown:
            return

        self.token_socket.settimeout(2.0)
        for i in range(self.max_failed_tokens):
            try:
                conn, addr = self.token_socket.accept()
            except:
                err_msg = 'ServerInterface: Failed accepting connection from %s.'
                err_msg += ' Try number: %d'
                logging.error(err_msg, self.username, i + 1, exc_info=True)
                continue

            conn.settimeout(1.0)
            if self.encrypt_enabled:
                self.data_socket = ssl.wrap_socket(conn, server_side=True,\
                    keyfile=ServerInterface.key_file_name,\
                    certfile=ServerInterface.cert_file_name)
            else:
                self.data_socket = conn

            # Get the token
            try:
                token = self.data_socket.recv(ServerInterface.token_size)
                while len(token) < ServerInterface.token_size:
                    token += self.data_socket.recv(ServerInterface.token_size)
            except:
                err_msg = 'ServerInterface: Failed receiving token from %s.'
                err_msg += ' Try number: %d'
                logging.error(err_msg, str(addr), i + 1)
                continue

            # Check the token
            if token == self.token:
                self.connected = True
                self.token_socket.close()
                self.peer_host = addr[0]
                self.peer_port = addr[1]
                msg = 'ServerInterface: Received token from %s. Connected.'
                logging.info(msg, str(addr))
                self.data_socket.settimeout(0.5)
                return

        # If we reached this point, we haven't received the token or we haven't
        # received any connect request when listening.
        logging.error('ServerInterface: Failed connecting for %s', self.username)
        self.token_socket.close()
        self.shutdown = True


    def get_port(self):
        """ Returns the port on which we bind to listen for the connection """
        return self.port


    def send_message(self, message, real_time=False):
        """
        Sends a message to the peer.
        message: The message to be sent. This must be a string.
        real_time: If True, then the message will be sent as it comes (not
        being added to the queue.
        """
        # If we did shutdown, we aren't sending messages
        if self.shutdown:
            return

        # If it's a real time message, send it right away
        if real_time:
            if not self.connected:
                err_msg = 'ServerInterface: Trying to send message without '
                err_msg += ' connected'
                logging.warning(err_msg)
                return

            sent_data = str(json.dumps([message])) + message_delimiter
            if not self._send(sent_data):
                err_msg = 'ServerInterface: Failed to send message to %s:%s'
                logging.warning(err_msg, str(self.peer_host),\
                                str(self.peer_port))
                return

            logging.debug('ServerInterface: Sending %s to %s:%s', str(message),\
                          str(self.peer_host), str(self.peer_port))
            return

        # Not a real time message
        self.message_queue_lock.acquire()
        self.message_queue.append(message)
        if not self.connected and len(self.message_queue) > self.max_messages:
            self.message_queue.popleft()
        self.message_queue_lock.release()


    def check_time(self):
        if time.time() - self.last_sent_time > self.timeout:
            return True
        return False


    def check_size(self):
        return len(self.message_queue) >= self.max_messages


    def flush_queue(self):
        if len(self.message_queue) is 0:
            return

        self.message_queue_lock.acquire()
        sent_list = list(self.message_queue)
        self.message_queue = []
        self.message_queue_lock.release()

        sent_data = str(json.dumps(sent_list)) + message_delimiter
        if not self._send(sent_data):
            err_msg = 'ServerInterface: Failed to send message to %s:%s'
            logging.warning(err_msg, str(self.peer_host),\
                            str(self.peer_port))
        self.last_sent_time = time.time()


    def close_connection(self):
        if not self.connected:
            # We are still connecting, but we should send the
            # connection closed response when the connection
            # is made.
            self.shutdown = True

        close_response = dict()
        close_response[ResponseFields.request_id] = -1
        close_response[ResponseFields.response_code] =\
            ResponseCodes.connection_closed
        sent_data = str(json.dumps(close_response)) + message_delimiter

        try:
            self._send(sent_data)
            self.data_socket.close()
            self.token_socket.close()
        except:
            return


    def _send(self, data):
        if not self.connected:
            return
        total_sent_b = 0
        length = len(data)
        self.data_socket_lock.acquire()
        try:
            while total_sent_b < length:
                sent = self.data_socket.send(data[total_sent_b:])
                if sent is 0:
                    self.shutdown = True
                    self.data_socket.close()
                    self.data_socket_lock.release()
                    return False
                total_sent_b += sent
        except:
            self.shutdown = True
            logging.error('ServerInterface: Failed to send data to %s:%s',\
                          str(self.peer_host), str(self.peer_port),\
                          exc_info=True)
        self.data_socket_lock.release()
        return not self.shutdown


    def run(self):
        # Wait for _listen green light

        self._connect()
        if not self.connected:
            self.shutdown = True
            return

        # Special case when we received a close_connection while connecting
        if self.shutdown:
            self.close_connection()
            return

        while True:
            if self.shutdown:
                msg = 'ServerInterface: Connection with %s:%s shutting down ...'
                logging.info(msg, str(self.peer_host), str(self.peer_port))
                break

            if self.check_time() or self.check_size():
                self.flush_queue()
            time.sleep(0.5)


