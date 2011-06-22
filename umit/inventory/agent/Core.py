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
import traceback

from umit.inventory.agent.Configs import AgentConfig
from umit.inventory.common import CorruptInventoryModule
from umit.inventory import common


class AgentMainLoop:

    def __init__(self, message_parser, configurations):
        """
        @message_parser: A parser which must implement the parse(message)
        method. It depends on implementation, but most likely, it will send
        the message trough UDP to the Notifications Server.
        """

        # The monitoring modules add the messages trough the add_message(msg)
        # method and are stored in the added_message_queue. Before parsing
        # the messages with _parse_messages(), the added_message_queue will 
        # be copied to the parsing_message_queue and be flushed.
        self.parsing_message_queue = []
        self.added_message_queue = []
        self.added_message_queue_lock = threading.Lock()
        self.main_loop_cond_var = threading.Condition()
        self.received_messages = False
        self.message_parser = message_parser
        self.modules = []
        self.conf = configurations


    def _parse_messages(self):
        """Parses each message in the self.parsing_message_queue"""
        for message in self.parsing_message_queue:
            self.message_parser.parse(message)


    def add_message(self, message):
        """
        Method which should be called by Monitoring Modules to add messages
        which should be later parsed by _parse_message(). Most likely, the
        parsing will involve sending the messages to the Notifications
        Server.
        """

        self.added_message_queue_lock.acquire()

        self.added_message_queue.append(message)
        self.main_loop_cond_var.acquire()
        self.main_loop_cond_var.notify()
        self.received_messages = True
        self.main_loop_cond_var.release()

        self.added_message_queue_lock.release()


    def run(self):
        """
        The actual main loop. It's signal based implemented trough the
        self.main_loop_cond_var condition variable. It will wait until there
        are messages to be parsed
        """
        try:
            # Load up the modules
            # TODO log this
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
                    traceback.print_exc()
                    continue

                self.modules.append(module_obj)

            # Start up the modules
            for module in self.modules:
                module.start()

            # The actual main loop
            while True:
                self.added_message_queue_lock.acquire()
                if self.received_messages:
                    self.parsing_message_queue = self.added_message_queue
                    self.added_message_queue = []
                    self.received_messages = False
                    self.added_message_queue_lock.release()

                    self._parse_messages()

                else:
                    self.main_loop_cond_var.acquire()
                    self.added_message_queue_lock.release()
                    self.main_loop_cond_var.wait(0.5)
                    self.main_loop_cond_var.release()
        except KeyboardInterrupt:
            return


class AgentNotificationParser:

    def __init__(self, configs):
        """
        The message parser should parse the messages and send them to the
        Notifications Server which is specified in the Configurations.
        It also offers the option to encrypt the messages if specified.
        """
        self.server_addr = configs.get_general_option(AgentConfig.server_addr)
        self.server_port = configs.get_general_option(AgentConfig.server_port)
        self.server_port = int(self.server_port)
        self.encrypt_enabled =\
                configs.get_general_option(AgentConfig.encrypt_enabled)


    def _encrypt(self, message):
        # Encrypts the message. TODO
        return message


    def parse(self, message):
        """
        Encrypts the message if specified and then send it to the Notifications
        Server.
        """
        if self.encrypt_enabled:
            sent_msg = self._encrypt(message)
        else:
            sent_msg = message

        print '-------------------------------------'
        print 'Sending message to ' + self.server_addr + ':' + str(self.server_port) + ' ...'
        print message
        print '-------------------------------------'
        # Send the message trough UDP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(sent_msg, (self.server_addr, self.server_port))


class CorruptAgentModule(CorruptInventoryModule):

    get_name = 2

    def __init__(self, module_name, module_path, err_type=0):
        CorruptInventoryModule.__init__(self, module_name,\
                module_path, err_type)
        if err_type == CorruptAgentModule.get_name:
            self.err_description = module_name + 'doesn\'t implement' +\
                    'the get_name() or it\'s return value is incorrect'
