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

from umit.inventory.server.Notification import Notification
from umit.inventory.server.Notification import NotificationFields
from umit.inventory.server.Configs import ServerConfig
from umit.inventory.common import message_delimiter
from umit.inventory.server.Module import ListenerServerModule

from twisted.internet import reactor
from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
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
        print 'forwarding ...'

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
        print 'subscribe request from %s' % username
        user = self.user_system.get_user(username)
        req_id = request.get_request_id()
        general_request = GeneralRequest(request)
        if not general_request.sanity_check():
            return
        subscribe_request = SubscribeGeneralRequest(general_request)
        if not subscribe_request.sanity_check():
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
        connection.send_message(json.dumps(response))


    def evaluate_get_configs_request(self, request, connection):
        pass


    def evaluate_set_configs_request(self, request, connection):
        pass


    def evaluate_restart_request(self, request, connection):
        #TODO
        pass


    def evaluate_search_request(self, request, connection):
        pass


    def evaluate_search_next_request(self, request, connection):
        pass


    def evaluate_search_stop_request(self, request, connection):
        pass


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
            connection = self.get_connection(request)
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



class Request:
    """ Request base class """

    def __init__(self, data, host, port):
        self.data = data
        self.host = host
        self.port = port

        self.request = None

        self.username = None
        self.password = None
        self.target = None
        self.request_id = None
        self.body = None


    def sanity_check(self):
        """
        Must be performed after initialisation.
        Also does the de-serialization of the request.
        """
        # Check it's JSON seriazable
        try:
            request = json.loads(self.data)
            self.request = request
        except:
            err_msg = 'ServerInterface: Received non-JSON serializable request'
            err_msg += ' from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port),\
                            exc_info=True)
            return False
        
        # Check the username
        try:
            self.username = request[RequestFields.username]
        except:
            err_msg = 'ServerInterface: Missing username in request from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port))
            return False

        # Check the password
        try:
            self.password = request[RequestFields.password]
        except:
            err_msg = 'ServerInterface: Missing password in request from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port))
            return False

        # Check the request id
        try:
            self.request_id = request[RequestFields.request_id]
        except:
            err_msg = 'ServerInterface: Missing request_id in request from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port))
            return False

        # Check the target
        try:
            self.target = request[RequestFields.target]
        except:
            err_msg = 'ServerInterface: Missing target in request from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port))

        # Check the body (optional)
        if RequestFields.body in request.keys():
            self.body = request[RequestFields.body]

        return True


    # Request fields

    def get_username(self):
        return self.username


    def get_password(self):
        return self.password


    def get_request_id(self):
        return self.request_id


    def get_target(self):
        return self.target


    def get_body(self):
        return self.body



class GeneralRequest:

    def __init__(self, request):
        self.request = request

        self.type = None
        self.body = None


    def sanity_check(self):
        """ Checks the fields. Must be called after initialization """
        # Check the type
        try:
            self.type = self.request.body[GeneralRequestBody.request_type]
        except:
            err_msg = 'ServerInterface: Missing type from general request'
            logging.warning(err_msg)
            return False

        # Check the body (optional)
        if GeneralRequestBody.request_body in self.request.body:
            self.body = self.request.body[GeneralRequestBody.request_body]

        return True


    def get_type(self):
        return self.type


    def get_body(self):
        return self.body



class ConnectGeneralRequest:

    def __init__(self, general_request):
        self.body = general_request.get_body()


    def sanity_check(self):
        try:
            self.encryption_enabled =\
                self.body[ConnectGeneralRequestBody.enable_encryption]
        except:
            err_msg = 'ServerInterface: Missing encrypt_enabled field from'
            err_msg += ' connect request'
            logging.warning(err_msg)
            return False

        return True


    def get_encryption_enabled(self):
        return self.encryption_enabled



class SubscribeGeneralRequest:

    def __init__(self, general_request):
        self.body = general_request.get_body()


    def sanity_check(self):
        try:
            self.protocol = self.body[SubscribeGeneralRequestBody.protocol]
        except:
            err_msg = 'ServerInterface: Missing protocol field from'
            err_msg += ' subscribe request'
            logging.warning(err_msg)
            return False

        try:
            self.hosts = self.body[SubscribeGeneralRequestBody.hosts]
        except:
            err_msg = 'ServerInterface: Missing hosts field from'
            err_msg += ' subscribe request'
            logging.warning(err_msg)
            return False

        try:
            self.types = self.body[SubscribeGeneralRequestBody.types]
        except:
            err_msg = 'ServerInterface: Missing types field from'
            err_msg += ' subscribe request'
            logging.warning(err_msg)
            return False

        return True


    def get_protocol(self):
        return self.protocol


    def get_hosts(self):
        return self.hosts


    def get_types(self):
        return self.types



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
        print 'in ...'
        self.message_queue_lock.acquire()
        self.message_queue.append(message)
        if not self.connected and len(self.message_queue) > self.max_messages:
            self.message_queue.popleft()
        self.message_queue_lock.release()
        print '... and out'


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



# Requests section

class RequestFields:
    """
    The mandatory fields in a request:
    * username: The username in the Server User System.
    * password: The password associated with the username in the Server User
      System. The username and password will be used to authenticate the user
      and check his permissions.
    * target: The target for the request. Can have one of the following values:
      - General: This is a general request that isn't conditioned by a the
        presence of a particular module.
      - [module_name]: This can be the name of a module (e.g. AgentListener,
        SNMPListener, etc) and the request body will be forwarded to be solved
        to the corresponding module (after authentication is done).
    * request_id: A positive integer identifying the request of the requesting
      side. It's mandatory for the requesting side to guarantee that it doesn't
      have 2 pending requests with the same request_id values. The response to
      the request will also contain the request_id field having the same value.
    * body: The actual body for the request which is dependent on the target
      value. For a 'General' target request, see GeneralRequestBody.
    """
    username = 'username'
    password = 'password'
    target = 'target'
    request_id = 'request_id'
    body = 'body'


class GeneralRequestBody:
    """
    The mandatory fields in a request having the 'GENERAL' target:
    * request_type: Identifies the type of the general request. This field can
      have one of the following values:
      - "CONNECT": The requesting side wants to connect to the
        Server. This is mandatory before sending any other request. See
        ConnectGeneralRequestBody for details about this request.
      - "SUBSCRIBE": The requesting side wants to subscribe to the Server to
        receive notifications as they come. This will ony forward notifications
        which are not reports. See SubscribeGeneralRequestBody for details
        about this request.
      - "UNSUBSCRIBE": The requesting side wants to stop receiving notifications
        from the Server. There isn't any associated body for this type.
      - "GET_MODULES": The requesting side wants to know which modules are
        installed and enabled on the Server. There isn't any associated body
        for this request.
      - "GET_CONFIGS": The requesting side wants to get the current
        configurations of the Server. There isn't any associated body for this
        type.
      - "SET_CONFIGS": The requesting side wants to set configurations on the
        Server. See SetConfigsGeneralRequestBody for details about this request.
      - "RESTART": The requesting side wants to restart the Server. There isn't
        any associated body for this type.
      - "SEARCH": The requesting side wants to search the notifications. See
        SearchGeneralRequestBody for details about this request.
      - "SEARCH_NEXT": The requesting side wants to get the next results for a
        search he already requested. See SearchNextGeneralRequestBody for
        details about this request.
      - "SEARCH_STOP": The requesting side wants to end getting results for a
        search. See SearchStopGeneralRequestBody for details about this request.
      - "ADD_USER": The requesting side wants to add a user to the Server User
        System. See AddUserGeneralRequestBody for details about this request.
      - "DEL_USER": The requesting side wants to delete a user from the Server
        User System. See DelUserGeneralRequestBody for details about this
        request.
      - "SET_USER": The requesting side wants to set permissions or a new
        password for a user. See SetUserGeneralRequestBody for details about
        this request.
      - "GET_USERS": The requesting side wants to get the list with all the
        users and their permission. There isn't any associated body for this
        type.
    """
    request_type = 'general_request_type'
    request_body = 'general_request_body'


class ConnectGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "CONNECT":
    * enable_encryption: If True, subsequent request/responses will use a SSL
      encrypted TCP connection. If False, a non-encrypted TCP connection will
      be used. Note: This can be overridden by the Server Configurations. See
      AuthenticationResponseBody.
    """
    enable_encryption = 'enable_encryption'


class SubscribeGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SUBSCRIBE":
    * protocol: The protocol for which the server wants to receive
      notifications. If the value is 'All', notifications from all the
      protocols will be sent.
    * hosts: A list of hosts for which the requesting side wants to receive
      notifications. An element of an list can be:
      - An IPv4 address.
      - An IPv6 address.
      - A host name.
      - A network address with it's subnet mask in the form of a string
        (e.g. '192.168.2.0/24')
      If the list is empty, the requesting side wants to receive notifications
      from all the hosts for which he has permissions.
    * types: A list of notification types for which the requesting side wants
      to receive notifications (or an empty list for all the types).

    Note: If a some of the subscription request fields aren't allowed by the
          user permissions, then only notifications that are allowed and
          requested will be sent, discarding the non-allowed requests.
    """
    protocol = 'protocol'
    hosts = 'hosts'
    types = 'types'


class SetConfigsGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SET_CONFIGS":
    * configs: A dictionary with the following structure:
      - At the top level there are entries having as keys the section name
        and as values dictionaries as described next.
      - The dictionary associated with a section have as keys the name of
        the option and as values the option value.

    Note: If the permission don't allow the user to set the configurations,
          then they won't be set.
    """
    configs = 'configs'


class SearchGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SEARCH":
    * fields: A list with the fields names that should be put in the response.
      If this list is empty, then all the fields will be returned.
    * spec: Used to filter the returned results. A dictionary with keys being
      names of the fields and as values lists with the following format:
      [<spec_id>, <spec_param_1>, ..., <spec_param_n>]. The parameters are
      based on the value of the spec_id. A list with the possible spec_id's
      and the corresponding format:
      - ['eq', <value>]: The field must be equal to <value>
      - ['neq', <value>]: The field must not be equal to <value>
      - ['gt', <value>]: The field must be greater than <value>
      - ['lt', <value>]: The field must be less than <value>
      - ['range', <value1>, <value2>]: The field must be greater than <value1>,
        but less than <value2>.
      - ['in', <value_1>, ..., <value_n>]: The field must be in the list
        [<value_1>, ..., <value_n>]
      - ['nin', <value_1>, ..., <value_n>]: The field must not be in the list
        [<value_1>, ..., <value_n>]
    * sort: A list of the fields that should be sorted. The order in which they
      will be considered for sorting will be from the first field in this list
      to the last one. Each entry in the list must be a list of 2 elements:
      [<field_name>, true|false], where the first element tells the name of
      the field to be sorted and the second element is the direction of sorting
      (true for Ascending, false for Descending).
    * search_id: A search id which will be must for getting the next items
      in the returned result.
    """
    fields = 'fields'
    spec = 'spec'
    sort = 'sort'
    search_id = 'search_id'


class SearchNextGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SEARCH_NEXT":
    * search_id: The Search for which we want to get the next results. This
      must be equal to the search_id in the initial "SEARCH" request.
    """
    search_id = 'search_id'


class SearchNextGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SEARCH_NEXT":
    * search_id: The search for which we want to stop getting results. This
      must be equal to the search_id in the initial "SEARCH" request.
    """
    search_id = 'search_id'


class AddUserGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "ADD_USER":
    * username: The name of the user to be added to the Server User System.
    * password: The password for the user to be added to the Server User System.
    * permissions: The permissions for the user. See UserPermissions class in
      umit.inventory.server.UserSystem for details.
    Note: If the requesting user doesn't have the permissions to add an user,
          then the request will be discarded.
    """
    username = 'username'
    password = 'password'


class DelUserGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "DEL_USER":
    * username: The name of the user to be deleted from the Server User System.

    Note: If the requesting user doesn't have the permissions to delete an user,
          then the request will be discarded.
    """
    username = 'username'


class SetUserGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "DEL_USER":
    * username: The name of the user for which we want to set permissions or
      the password.
    * permissions: The new permissions for the user. See UserPermissions class
      in umit.inventory.server.UserSystem for details.
    * set_permissions: If True, then the permissions will be set according to
      the permissions field.
    * password: The new password for the user.
    * set_password. If True, then the password will be set according to the
      password field.
    """
    username = 'username'
    permissions = 'permissions'
    set_permissions = 'set_permissions'
    password = 'password'
    set_password = 'password'


# Responses section

class ResponseCodes:
    accepted = 200
    auth_denied = 401
    missing_connection = 403
    missing_permissions = 400
    invalid = 406
    connection_closed = 100


class ResponseFields:
    """
    The mandatory fields in a response:
    * request_id: The request_id of the associated request with this response.
      For asynchronous responses (e.g. notifications) this is -1.
    * response_code: An int showing the state of the response:
      - 200: The request was accepted.
      - 401: Authentication denied.
      - 403: Request without prior to a connection.
      - 400: Missing permissions.
      - 406: Invalid request.
      - 100: Connection Closed
    * response_type: A string showing the response type. This is useful only
      for asynchronous response (request_id == -1). For synchronous responses,
      the request_id is sufficient to determine the type of the response.
      For 'SUBSCRIBE' asynchronous responses, this field will be set to
      'SUBSCRIBE_RESPONSE' and the body will contain a list with notifications.
    * body: Based on the request_id which will identify the request type, then
      this will contain the response body. For requests having the 'GENERAL'
      target and based on the 'general_request_type' field, the following
      responses bodies are possible:
      - 'CONNECT': ConnectResponseBody
      - 'GET_MODULES': GetModulesResponseBody
      - 'GET_CONFIGS': GetConfigsResponseBody
      - 'SEARCH': SearchResponseBody
      - 'SEARCH_NEXT': SearchResponseBody
      - 'GET_USERS': GetUsersResponseBody

    Note: The body field is present only if response_code is equal 200.
    """
    request_id = 'request_id'
    response_code = 'response_code'
    response_type = 'response_type'
    body = 'body'


class ConnectResponseBody:
    """
    The response for a 'CONNECT' general request. Fields:
    * permissions: The permissions for the user as they are stored on the
      server. See umit.inventory.server.UserSystem.UserPermissions (the value
      here is what is returned by the serialize method). This field is only
      present if authentication_accepted is True.
    * data_port: The port on the Server side which will forward the data to
      the requesting_side. It's the port used to send all the other responses.
    * encryption_enabled: If the newly opened TCP port uses SSL this is True.
      If the Server is configured to use SSL for the data port, this will be
      True, otherwise it will be equal to the 'enable_encryption' field in
      AuthenticateGeneralRequestBody.
    * protocols: A list with the listening protocols present on the server.
    """
    permissions = 'permissions'
    data_port = 'data_port'
    encryption_enabled = 'encryption_enabled'
    token = 'token'
    protocols = 'protocols'


class GetModulesResponseBody:
    """
    The response for a 'GET_MODULES' general request. Fields:
    * modules: A list with the modules installed and enabled on the server.
    """
    modules = 'modules'


class GetConfigsResponseBody:
    """
    The response for a 'GET_CONFIGS' general request. Fields:
    * configs: A dictionary with the following structure:
      - At the top level there are entries having as keys the section name
        and as values dictionaries as described next.
      - The dictionary associated with a section have as keys the name of
        the option and as values the option value.
    """
    configs = 'configs'


class SearchResponseBody:
    """
    The response for a 'SEARCH' and 'SEARCH_NEXT' general requests. Fields:
    * results: A list with the results JSON serialized as it was requested
      in the first 'SEARCH' request.
    * current_position: An integer representing the current start position
      for this list with returned results in all the returned results.
    * total_results_count: An integer representing the total results count.
    """
    results = 'results'
    current_position = 'current_position'
    total_results_count = 'total_results_count'


class GetUsersResponseBody:
    """
    The response for a 'GET_USERS' general request. Fields:
    * users: A list with the user names.
    * permissions: A list with the corresponding permissions for the user
      names in the users list.
      See umit.inventory.server.UserSystem.UserPermissions (the value
      here is what is returned by the serialize method). This field is only
      present if authentication_accepted is True.
    """
    users = 'users'
    permissions = 'permissions'