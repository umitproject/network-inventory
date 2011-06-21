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
from threading import Thread

from umit.inventory.agent import Core
from umit.inventory.common import AgentNotificationParser


class MonitoringModule(Thread):
    """
    The interface which should be implemented by the monitoring modules.

    self.options: A dictionary with the options for this module which are
    read from the configuration file.
    """

    def __init__(self, configs, agent_main_loop):
        Thread.__init__(self)

        # Initialize the default settings for this module. Will be
        # overwritten by the next pargraph if they are set in the config file.
        self.options = dict()
        self.init_default_settings()

        # Get the options from the configs and save them
        module_config_options = configs.items(self.get_name())
        for option in module_config_options:
            self.options[option[0]] = option[1]

        # Save the agent Main Loop which will get the Module's messages
        self.agent_main_loop = agent_main_loop


    def get_name(self):
        """Must be implemented by the Monitoring Module"""
        raise MonitoringModule.NotImplemented('get_name')


    def send_message(self, message, msg_type, fields):
        """
        Used by the Monitoring Module which inherents this class
        to send the message to the Notifications Server.
        message: The actual message text.
        msg_type: The type of the message. See umit.inventory.common
        fields: A dictionary with the module specific fields.
        """
        notification = AgentNotificationParser.parse(message, msg_type,\
                fields, self.get_name())
        self.agent_main_loop.add_message(notification)


    def run(self):
        """The Monitoring module main loop. Must be implemented."""
        raise MonitoringModule.NotImplemented('run')


    def shutdown(self):
        """ Called when the module must shututdown. Must be implemented """
        raise MonitoringModule.NotImplemented('shutdown')
    

    def init_default_settings(self):
        """
        Sets in the self.options dictionary the default settings for this
        module. Should be implemented by all the monitoring modules if they
        have specific settings they expect, as if those settings aren't located
        in the config file, an exception will be generated.
        """
        pass


    class NotImplemented(Exception):

        def __init__(self, func_name):
            self.err_message = 'Method ' + func_name + '() must be implemented'
            self.err_message += ' when extending the MonitoringModule class'

        def __str__(self):
            return repr(self.err_message)

