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
import sys

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



class AgentNotificationParser:

    def __init__(self, configs):
        """
        The message parser should parse the messages and send them to the
        Notifications Server which is specified in the Configurations.
        It also offers the option to encrypt the messages if specified.
        """
        self.server_addr = configs.get_general_option(AgentConfig.server_addr)
        self.server_port = configs.get_general_option(AgentConfig.server_port)
        self.server_port = int(self.server_port);
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



def load_module(module_name, module_path, configs, agent_main_loop):
    """
    Loads at runtime a monitoring module located in the file called
    [module_name].py at the path specified by module_path. In the file
    there must be a class which extends the MonitoringModule class and which
    is called [module_name].
    """
    path_tokens = module_path.split('/') #TODO - for Windows
    modname = ''
    for path_token in path_tokens:
        modname += path_token + '.'
    modname += module_name

    # Try importing from the path. If we fail at this step, then the path
    # is invalid or we don't have permissions.
    try:
        exec('import %s' % modname)
    except:
        raise CorruptModule(module_name, module_path,\
                CorruptModule.corrupt_path)

    # Try to get a reference to the class for this Monitoring Module.
    try:
        mod_class = sys.modules[modname].__dict__[module_name]
    except:
        raise CorruptModule(module_name, module_path,\
                CorruptModule.corrupt_file)

    # Initialize the object and test it's corectness
    module_obj = mod_class(configs, agent_main_loop)
    if module_obj.get_name() != module_name:
        raise CorruptModule(module_name, module_path,\
                CorruptModule.get_name)

    return module_obj


class CorruptModule(Exception):
    """
    An exception generated when the module couldn't be loaded. Cases:
    corrupt_path: The file called [module_name].py couldn't be located at the
                  specified path.
    corrupt_file: The file [module_name].py was found at the specified path,
                  but it didn't contained a class called [module_name].
    get_name:     The module doesn't implement the get_name() function or the
                  result is incorrect.
    """

    corrupt_path = 0
    corrupt_file = 1
    get_name = 2

    def __init__(self, module_name, module_path, err_type=0):
        self.err_message = 'Module ' + str(module_name) + ' fatal error: '
        if err_type == CorruptModule.corrupt_path:
            self.err_description = module_path + '/' + module_name + '.py' +\
                    ' not found or missing permissions'
        elif err_type == CorruptModule.corrupt_file:
            self.err_description = module_path + '/' + module_name + '.py' +\
                    ' doesn\'t contain a class called ' + module_name
        elif err_type == CorruptModule.get_name:
            self.err_description = module_name + ' doesn\'t implement the\
                    get_name() method or it\'s return value is incorrect'
        else:
            self.err_description = 'Undefined error'


    def __str__(self):
        return repr(self.err_message + self.err_description)


