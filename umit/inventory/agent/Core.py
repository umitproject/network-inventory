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

import threading
import socket
import logging
import json
import time
import ssl
from OpenSSL import crypto
import os
import tempfile
from collections import deque

from umit.inventory.agent.Configs import AgentConfig
from umit.inventory.common import CorruptInventoryModule
from umit.inventory.common import AgentFields
from umit.inventory.common import AgentCommandFields
from umit.inventory import common
from umit.inventory.common import message_delimiter
from umit.inventory.common import keep_alive_timeout
from umit.inventory.Configuration import InventoryConfig


class AgentMainLoop:

    def __init__(self, message_parser, configurations):
        """
        @message_parser: A parser which must implement the parse(message)
        method. It depends on implementation, but most likely, it will send
        the message trough UDP to the Notifications Server.
        """
        logging.info('Initing the AgentMainLoop ...')

        # The monitoring modules add the messages trough the add_message(msg)
        # method and are stored in the added_message_queue. Before parsing
        # the messages with _parse_messages(), the added_message_queue will 
        # be copied to the parsing_message_queue and be flushed.
        self.parsing_message_queue = []
        self.added_message_queue = []
        self.added_message_queue_lock = threading.Lock()
        self.received_messages = False
        self.message_parser = message_parser
        self.modules = []
        self.conf = configurations
        self.keep_alive_timer = time.time()

        self.command_connections = []
        self.command_id_to_connection = {}
        self.command_connections_lock = threading.Lock()

        # Mapping command names to functions
        self.command_functions = {'GET_CONFIGS' : self.handle_get_configs,\
                                  'SET_CONFIGS' : self.handle_set_configs,\
                                  'RESTART' : self.handle_restart,\
                                  'CLOSE_CONNECTION' : self.handle_close_connection,\
                                  }
        
        # If we should shutdown
        self.shutdown = False

        # Get the polling time for the loop
        self.polling_time =\
                float(self.conf.get_general_option(AgentConfig.polling_time))

        # Authentication options
        self.auth_enabled =\
            configurations.get_general_option(AgentConfig.auth_enabled)
        self.username = configurations.get_general_option(AgentConfig.username)
        self.password = configurations.get_general_option(AgentConfig.password)

        # Start the command listener
        if not self.auth_enabled:
            username = None
            password = None
            logging.info('Starting the CommandListener with auth disabled ...')
        else:
            username = self.username
            password = self.password
            logging.info('Starting the CommandListener with auth enabled ...')
        self.command_listener = CommandListener(self, username, password)
        message_parser.set_command_port(self.command_listener.get_command_port())
        logging.info('CommandListener is using port %d to receive commands',\
                     self.command_listener.get_command_port())
        self.command_listener.start()
        logging.info('CommandListener started')


    def _parse_messages(self):
        """Parses each message in the self.parsing_message_queue"""
        for message in self.parsing_message_queue:
            # Method returns False in case of a fatal error
            if not self.message_parser.parse(message):
                self.shutdown = True


    def add_message(self, message):
        """
        Method which should be called by Monitoring Modules to add messages
        which should be later parsed by _parse_message(). Most likely, the
        parsing will involve sending the messages to the Notifications
        Server.
        """

        self.added_message_queue_lock.acquire()

        self.added_message_queue.append(message)
        self.received_messages = True

        self.added_message_queue_lock.release()


    def add_command_connection(self, command_connection):
        """ Called when a new command connection was created """
        self.command_connections_lock.acquire()
        self.command_connections.append(command_connection)
        self.command_connections_lock.release()


    def close_command_connection(self, command_connection):
        """ Called when a command connection was closed """
        self.command_connections_lock.acquire()
        try:
            self.command_connections.remove(command_connection)
            for command_id in self.command_id_to_connection.keys():
                if self.command_id_to_connection[command_id] == command_connection:
                    del self.command_id_to_connection[command_id]
        except:
            pass
        self.command_connections_lock.release()

        
    def handle_command(self, target, command, body, command_id,\
                       command_connection):
        # If this command_id is already mapped to a connection, close the
        # previous one
        self.command_connections_lock.acquire()
        if command_id in self.command_id_to_connection.keys():
            del_command_connection = self.command_id_to_connection[command_id]
            del_command_connection.shutdown()
            self.command_connections.remove(del_command_connection)
            del self.command_id_to_connection[command_id]
        self.command_connections_lock.release()

        # Mapping command id's to their connection
        self.command_id_to_connection[command_id] = command_connection

        if target == 'GENERAL':
            try:
                self.command_functions[command](command, command_id, body,\
                                                command_connection)
            except:
                logging.warning('Received invalid command name', exc_info=True)
            return
        else:
            for module in self.modules:
                module_name = module.get_name()
                if target == module_name:
                    module.handle_command(command, command_id, body,\
                                          command_connection)
                    return
            logging.warning('Received invalid command target')


    def handle_set_configs(self, command, command_id, body, command_connection):
        configs = body
        try:
            for section in configs.keys():
                options = configs[section]
                for option_name in options.keys():
                    option_value = options[option_name]
                    self.conf.set(section, option_name, option_value)
        except:
            logging.warning('Received invalid SET_CONFIGS body', exc_info=True)
            command_connection.shutdown()
            return

        command_connection.shutdown()

        # Update the module configs
        for module in self.modules:
            module.update_configs()

        # Store the configs
        self.conf.save_settings()
    

    def handle_get_configs(self, command, command_id, body, command_connection):
        configs = dict()
        section_names = self.conf.sections()
        for section_name in section_names:
            section = dict()
            option_names = self.conf.options(section_name)
            for option_name in option_names:
                option_value = self.conf.get(section_name, option_name)
                section[option_name] = option_value
            configs[section_name] = section

        response = AgentNotificationParser.encode_command_response(\
            configs, command, command_id)

        command_connection.send(response)
        command_connection.shutdown()


    def handle_restart(self, command, command_id, body, command_connection):
        # TODO
        logging.info('Restart required by Notifications Server')
        command_connection.shutdown()


    def handle_close_connection(self, command, command_id, body,\
                                command_connection):
        closed_command_id = body
        
        self.command_connections_lock.acquire()
        try:
            del_command_connection =\
                    self.command_id_to_connection[closed_command_id]
        except:
            return

        del_command_connection.shutdown()
        self.command_connections.remove(del_command_connection)
        del self.command_id_to_connection[closed_command_id]
        self.command_connections_lock.release()
        command_connection.shutdown()
        

    def run(self):
        """
        The actual main loop. It's signal based implemented trough the
        self.main_loop_cond_var condition variable. It will wait until there
        are messages to be parsed
        """
        try:
            # Load up the modules
            logging.info('Loading up the modules ...')
            modules_names = self.conf.get_modules_list()
            for module_name in modules_names:
                try:
                    module_path = self.conf.module_get_option(module_name,\
                            AgentConfig.module_path)
                    module_obj = common.load_module(module_name,\
                            module_path, self.conf, self)

                    # Do a sanity check to test the module is correct
                    try:
                        module_name = module_obj.get_name()
                    except:
                        raise CorruptAgentModule(module_name, module_path,\
                                CorruptAgentModule.get_name)
                    if module_name != module_obj.get_name():
                        raise CorruptAgentModule(module_name, module_path,\
                                CorruptAgentModule.get_name)
        
                except Exception, e:
                    logging.error('Loading failed for module %s',\
                                 module_name, exc_info=True)
                    continue

                logging.info('Loaded module %s', module_obj.get_name())
                self.modules.append(module_obj)
            logging.info('Done loading modules.')

            # Store the modules configurations
            logging.info('Saving current settings to the config file ...')
            self.conf.save_settings()
            logging.info('Current settings saved to the config file.')

            # Start up the modules
            logging.info('Starting modules threads ...')
            for module in self.modules:
                module.start()
            logging.info('Started modules threads.')

            logging.info('Activating modules ...')
            # Activate the modules
            for module in self.modules:
                module_enabled = self.conf.get(module.get_name(),\
                        InventoryConfig.module_enabled)
                if module_enabled:
                    module.activate()
            logging.info('Done activating modules.')

            # Send the keep-alive message
            logging.info('Sending first KEEP_ALIVE')
            self.message_parser.send_keep_alive()
            logging.info('Sent first KEEP_ALIVE')
            
            # The actual main loop
            logging.info('Starting the Agent Main Loop ...')
            while True:
                if self.shutdown:
                    # Send the going-down message
                    self.message_parser.send_going_down()
                    logging.info('Shutting down ...')
                    break

                # Test if we should send the keep-alive message
                if self.keep_alive_timer + keep_alive_timeout < time.time():
                    self.message_parser.send_keep_alive()
                    self.keep_alive_timer = time.time()

                self.added_message_queue_lock.acquire()
                if self.received_messages:
                    self.parsing_message_queue = self.added_message_queue
                    self.added_message_queue = []
                    self.received_messages = False
                    self.added_message_queue_lock.release()

                    self._parse_messages()
                else:
                    self.added_message_queue_lock.release()

                time.sleep(self.polling_time)

        except KeyboardInterrupt:
            return


class AgentNotificationParser:
    """ Will send the notifications to the Notifications Server """

    username = ''
    password = ''
    auth_enabled = False

    def __init__(self, configs):
        """
        The message parser should parse the messages and send them to the
        Notifications Server which is specified in the Configurations.
        It also offers the option to encrypt the messages if specified trough
        SSL.
        """
        self.command_port = -1
        self.server_addr = configs.get_general_option(AgentConfig.server_addr)
        self.server_port = configs.get_general_option(AgentConfig.server_port)
        self.server_port = int(self.server_port)
        self.ssl_enabled = configs.get_general_option(AgentConfig.ssl_enabled)

        self.notification_queue = deque()
        self.max_queue_size =\
            configs.get_general_option(AgentConfig.max_notification_queue_size)
        self.max_queue_size = int(self.max_queue_size)

        # Authentication options
        AgentNotificationParser.auth_enabled =\
            configs.get_general_option(AgentConfig.auth_enabled)
        AgentNotificationParser.username =\
            configs.get_general_option(AgentConfig.username)
        AgentNotificationParser.password =\
            configs.get_general_option(AgentConfig.password)


    def set_command_port(self, command_port):
        self.command_port = command_port


    def send_keep_alive(self):
        message_obj = dict()
        message_obj[AgentFields.command_port] = self.command_port
        message_obj[AgentFields.message_type] = 'KEEP_ALIVE'
        message_obj[AgentFields.hostname] = socket.gethostname()
        message_obj[AgentFields.timestamp] = time.time()

        # Optional authentication fields
        if AgentNotificationParser.auth_enabled:
            message_obj[AgentFields.username] = self.username
            message_obj[AgentFields.password] = self.password

        self.parse(json.dumps(message_obj))


    def send_going_down(self):
        message_obj = dict()
        message_obj[AgentFields.message_type] = 'GOING_DOWN'
        message_obj[AgentFields.hostname] = socket.gethostname()
        message_obj[AgentFields.timestamp] = time.time()

        # Optional authentication fields
        if AgentNotificationParser.auth_enabled:
            message_obj[AgentFields.username] = AgentNotificationParser.username
            message_obj[AgentFields.password] = AgentNotificationParser.password

        self.parse(json.dumps(message_obj))


    def parse(self, message, emptying_queue=False):
        """
        Sends the notification to the Notifications Server. If configured, it
        will use a SSL connection to send it.

        Returns False if a fatal error is encountered.
        """
        logging.debug('Trying to send notification to %s:%d:\n%s',\
                self.server_addr, self.server_port, message)

        # Send trough SSL
        if self.ssl_enabled:
            s = socket.socket()
            try:
                s = ssl.wrap_socket(s)
            except:
                logging.critical('Missing SSL support. Install OpenSSL.')
                return False

            # Connecting to the Notifications Server
            try:
                s.connect((self.server_addr, self.server_port))
            except:
                error_msg = 'Failed to connect to Server at %s:%s. '
                error_msg += 'Trying to send notification later:\n %s'
                logging.error(error_msg, self.server_addr, self.server_port,\
                              message, exc_info=True)

                # Storing the notification to the queue to try later to send it
                self.notification_queue.appendleft(message)

                # If we reached the maximum limit of the queue, we shut down
                if len(self.notification_queue) == self.max_queue_size:
                    logging.critical('Max notification queue size (%d) reached',\
                                     self.max_queue_size)
                    return False
                return True

            # Successfully connected. Sending message.
            sent_data = str(message) + message_delimiter
            total_sent_b = 0
            length = len(sent_data)
            try:
                while total_sent_b < length:
                    sent = s.send(sent_data[total_sent_b:])
                    if sent is 0:
                        err_msg = 'Failed to send notification to Server.\n'
                        err_msg += 'send() returned 0'
                        logging.error(err_msg)
                        s.close()
                        return False
                    total_sent_b += sent
            except:
                logging.error('Failed to send notification to Server', exc_info=True)
            s.close()

            # If we got here, the Server is running so we can try to send
            # the notifications we have in the queue (if any)
            if not emptying_queue:
                self.send_notifications_from_queue()

            logging.info('Successfully sent notification.')
            return True
        # Send trough UDP
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(message, (self.server_addr, self.server_port))
            logging.info('Successfully sent notification.')
            return True


    def send_notifications_from_queue(self):
        """ Tries to send the notifications which are present in the queue """
        if len(self.notification_queue) is 0:
            return

        sent_items = 0
        while len(self.notification_queue) > 0:
            initial_size = len(self.notification_queue)

            # Trying to send the notification
            notification = self.notification_queue.pop()
            self.parse(notification, True)

            # If it returned to the queue, we failed.
            if initial_size == len(self.notification_queue):
                break
            sent_items += 1

        if sent_items is not 0:
            logging.info('Sent %d notifications from the queue.',\
                         sent_items)


    @staticmethod
    def encode(message, short_message, msg_type, fields, is_report, module):
        """Encodes the message into the internal format (JSON)"""
        message_obj = dict()
        message_obj[AgentFields.message] = message
        message_obj[AgentFields.short_message] = short_message
        message_obj[AgentFields.message_type] = msg_type
        message_obj[AgentFields.timestamp] = time.time()
        message_obj[AgentFields.monitoring_module] = module
        message_obj[AgentFields.hostname] = socket.gethostname()
        message_obj[AgentFields.module_fields] = dict()
        message_obj[AgentFields.is_report] = is_report
        for i in fields.keys():
            message_obj[AgentFields.module_fields][i] = fields[i]

        # Optional authentication fields
        if AgentNotificationParser.auth_enabled:
            message_obj[AgentFields.username] = AgentNotificationParser.username
            message_obj[AgentFields.password] = AgentNotificationParser.password

        return json.dumps(message_obj)


    @staticmethod
    def encode_command_response(command_fields, command, command_id=-1):
        """ Used to encode a command response. """
        message_obj = dict()
        message_obj[AgentFields.hostname] = socket.gethostname()
        message_obj[AgentFields.timestamp] = time.time()
        message_obj[AgentFields.message_type] = 'COMMAND_RESPONSE'
        message_obj[AgentFields.command_id] = command_id
        message_obj[AgentFields.command] = command
        message_obj[AgentFields.command_response_fields] = command_fields

        if AgentNotificationParser.auth_enabled:
            message_obj[AgentFields.username] = AgentNotificationParser.username
            message_obj[AgentFields.password] = AgentNotificationParser.password

        return json.dumps(message_obj)



class CommandListener(threading.Thread):

    min_port = 10001
    max_port = 30000

    # SSL certificate expiration: 10 years
    cert_expire = 316224000

    # SSL files
    cert_file_name = os.path.join(tempfile.gettempdir(),\
                                  'umit_agent.cert')
    key_file_name = os.path.join(tempfile.gettempdir(),\
                                 'umit_agent.key')


    def __init__(self, main_loop, username=None, password=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.main_loop = main_loop

        # Authentication dependent settings
        self.auth_enabled = username is not None
        if not self.auth_enabled:
            self.username = None
            self.password = None
        else:
            self.username = username
            self.password = password

        self.shutdown_lock = threading.Lock()
        self.should_shutdown = False

        self.command_port = None
        self.command_socket = socket.socket()
        self._generate_ssl_files()
        if not self.ssl_files_generated:
            return
        self._bind()


    def _generate_ssl_files(self):
        # Certificate and key files only for this session
        try:
            key_file = open(self.key_file_name, 'w')
            cert_file = open(self.cert_file_name, 'w')
        except:
            err_msg = 'Failed generated command port SSL files.\n'
            err_msg += 'For command functionality ensure permissions at %s' %\
                       tempfile.gettempdir()
            err_msg += ' or run the agent with administrative privileges.'
            logging.error(err_msg)
            self.ssl_files_generated = False
            return

        # Generate the key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 1024)

        # Generate the certificate
        cert = crypto.X509()
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(self.cert_expire)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha1')

        # Write to files
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        key_file.close()
        cert_file.close()
        self.ssl_files_generated = True


    def _bind(self):
        # Find an open socket
        for port in range(self.min_port, self.max_port):
            try:
                self.command_socket.bind(('0.0.0.0', port))
            except:
                continue
            self.command_port = port
            break

        if self.command_port is None:
            logging.error('Failed binding to command port')
        else:
            logging.info('Listening for commands on port %d', self.command_port)
            
        self.command_socket.listen(1)


    def _accept_connections(self):
        if not self.ssl_files_generated:
            return
        conn, addr = self.command_socket.accept()
        peer_host = addr[0]
        peer_port = addr[1]
        data_socket = ssl.wrap_socket(conn, server_side=True,\
                                      keyfile=self.key_file_name,\
                                      certfile=self.cert_file_name)
        logging.info('Accepted command connection from %s:%s',\
                     str(peer_host), str(peer_port))

        command_connection = CommandConnection(data_socket,\
                self.main_loop, self.username, self.password)
        command_connection.start()
        self.main_loop.add_command_connection(command_connection)


    def get_command_port(self):
        return self.command_port


    def shutdown(self):
        self.shutdown_lock.acquire()
        self.should_shutdown = True
        self.shutdown_lock.release()


    def run(self):
        if not self.ssl_files_generated:
            return

        while True:
            self.shutdown_lock.acquire()
            if self.should_shutdown:
                self.shutdown_lock.release()
                break
            self.shutdown_lock.release()
        
            self._accept_connections()
            


class CommandConnection(threading.Thread):

    def __init__(self, data_socket, main_loop, username=None, password=None):
        threading.Thread.__init__(self)
        self.daemon = True

        self.data_socket = data_socket
        self.main_loop = main_loop
        self.buffer = ''

        self.shutdown_lock = threading.Lock()
        self.should_shutdown = False

        peer = self.data_socket.getpeername()
        self.peer_host = str(peer[0])
        self.peer_port = str(peer[1])

        # Authentication dependent settings
        self.auth_enabled = username is not None
        self.username = username
        self.password = password


    def recv(self):
        chunk = []
        while message_delimiter not in chunk:
            try:
                chunk = self.data_socket.recv(4096)
            except:
                logging.error('Failed receiving command from %s:%s',\
                    self.peer_host, self.peer_port)
                return None

            if chunk == '':
                return None
            self.buffer += chunk
        buffer_parts = self.buffer.split(message_delimiter)
        self.buffer = buffer_parts[1]
        logging.debug('Received message from %s:%s.\n%s',\
                      self.peer_host, self.peer_port, buffer_parts[0])
        return buffer_parts[0]


    def send(self, data):
        self.data_socket.setblocking(0)
        total_sent_b = 0
        data += message_delimiter
        length = len(data)

        try:
            while total_sent_b < length:
                sent = self.data_socket.send(data[total_sent_b:])
                if sent is 0:
                    logging.error('Failed sending command data from %s:%s',\
                                  self.peer_host, self.peer_port)
                    self.data_socket.setblocking(1)
                    return False

                total_sent_b += sent
        except:
            logging.error('Failed sending command data from %s:%s',\
                          self.peer_host, self.peer_port)

            self.data_socket.setblocking(1)
            return False

        logging.debug('Sent command response to %s:%s.\n %s',\
                      self.peer_host, self.peer_port, data)

        self.data_socket.setblocking(1)
        return True


    def handle_command(self, message):
        try:
            command = json.loads(message)
        except:
            logging.warning('Received not JSON-seriazable command from %s:%s',\
                            self.peer_host, self.peer_port)
            return False
        
        # Get authentication data
        try:
            if self.auth_enabled:
                username = command[AgentCommandFields.username]
                password = command[AgentCommandFields.password]
            else:
                username = None
                password = None
        except:
            err_msg = 'Missing username and/or password in command from %s:%s'
            logging.warning(err_msg, self.peer_host, self.peer_port)
            return False

        # Authenticate if configured so
        if self.auth_enabled:
            if username != self.username or password != self.password:
                err_msg = 'Authentication failed in command from %s:%s'
                logging.warning(err_msg, self.peer_host, self.peer_port)
                return False

        try:
            target = str(command[AgentCommandFields.target])
            command_id = int(command[AgentCommandFields.command_id])
            command_name = str(command[AgentCommandFields.command])
            body = command[AgentCommandFields.body]
        except:
            err_msg = 'Received invalid command from %s:%s'
            logging.warning(err_msg, self.peer_host, self.peer_port,\
                            exc_info=True)
            return False

        self.main_loop.handle_command(target, command_name,\
                                      body, command_id, self)
        return True
        
    
    def shutdown(self):
        self.shutdown_lock.acquire()
        self.should_shutdown = True
        self.shutdown_lock.release()

        try:
            self.data_socket.close()
        except:
            pass
        self.main_loop.close_command_connection(self)


    def run(self):
        while True:
            self.shutdown_lock.acquire()
            if self.should_shutdown:
                self.shutdown_lock.release()
                break
            self.shutdown_lock.release()

            message = self.recv()
            if message is None:
                self.shutdown()
                break

            if not self.handle_command(message):
                self.shutdown()
                break



class CorruptAgentModule(CorruptInventoryModule):

    get_name = 2

    def __init__(self, module_name, module_path, err_type=0):
        CorruptInventoryModule.__init__(self, module_name,\
                module_path, err_type)
        if err_type == CorruptAgentModule.get_name:
            self.err_description = module_name + 'doesn\'t implement' +\
                    'the get_name() or it\'s return value is incorrect'