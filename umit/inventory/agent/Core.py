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

from umit.inventory.agent.Configs import AgentConfig

class AgentMainLoop:

    def __init__(self, message_parser):
        """
        @message_parser: A parser which must implement the parse(message)
        method. It dependens on implementation, but most likely, it will send
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


    def _parse_message(self):
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
                self.main_loop_cond_var.wait()
                self.main_loop_cond_var.release()



class AgentMessageParser:

    def __init__(self, configs):
        """
        The message parser should parse the messages and send them to the
        Notifications Server which is specified in the Configurations.
        It also offers the option to encrypt the messages if specified.
        """
        self.server_addr = configs.get_general_option(AgentConfig.server_addr)
        self.server_port = configs.get_general_option(AgentConfig.server_port)
        self.encrypt_enabled =\
                configs.get_general_option(AgentConfig.encrypt_enabled)


    def parse(self, message):
        """
        Encrypts the message if specified and then send it to the Notifications
        Server.
        """
        pass


