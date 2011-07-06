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
from collections import deque

from umit.inventory.agent.Configs import AgentConfig
from umit.inventory.common import CorruptInventoryModule
from umit.inventory.common import AgentFields
from umit.inventory import common
from umit.inventory.common import message_delimiter


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

        # If we should shut-down
        self.shutdown = False

        # Get the polling time for the loop
        self.polling_time =\
                float(self.conf.get_general_option(AgentConfig.polling_time))

        # Authentication options
        self.auth_enabled =\
            configurations.get_general_option(AgentConfig.auth_enabled)
        self.username = configurations.get_general_option(AgentConfig.username)
        self.password = configurations.get_general_option(AgentConfig.password)


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
                if not self.conf.module_get_enable(module_name):
                    continue
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

            # Start up the modules
            for module in self.modules:
                module.start()

            # The actual main loop
            logging.info('Starting the Agent Main Loop')
            while True:
                if self.shutdown:
                    logging.info('Shutting down ...')
                    break
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
            return True
        # Send trough UDP
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(message, (self.server_addr, self.server_port))


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


class CorruptAgentModule(CorruptInventoryModule):

    get_name = 2

    def __init__(self, module_name, module_path, err_type=0):
        CorruptInventoryModule.__init__(self, module_name,\
                module_path, err_type)
        if err_type == CorruptAgentModule.get_name:
            self.err_description = module_name + 'doesn\'t implement' +\
                    'the get_name() or it\'s return value is incorrect'