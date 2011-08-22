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

import json
import logging
from umit.inventory.Configuration import InventoryConfig


class ServerModule:
    """The interface for a generic ServerModule."""

    def __init__(self, configs, shell):
        logging.info('Initializing module %s', self.get_name())
        self.configs = configs
        self.shell = shell

        # Initialize to default settings
        self.options = dict()
        self.init_default_settings()

        # Set the module specific options
        self.options[InventoryConfig.is_module] = True
        self.options[InventoryConfig.module_enabled] = True

        # Get the options from the configs and save them
        if not self.configs.has_section(self.get_name()):
            self.configs.add_section(self.get_name())
        
        module_options = self.configs.options(self.get_name())
        for option in module_options:
            self.options[option] = self.configs.get(self.get_name(), option)

        # Save the configurations
        for option_name in self.options.keys():
            self.configs.set(self.get_name(), option_name,
                             self.options[option_name])

        logging.info('Initialized module %s with options:\n%s', self.get_name(),
                     json.dumps(self.options, sort_keys=True, indent=4))

        if self.is_enabled():
            logging.info('Module %s is enabled.', self.get_name())
        else:
            logging.info('Module %s is disabled.', self.get_name())


    def activate(self):
        """
        Called when the module is enabled.
        Should be implemented.
        """
        pass


    def deactivate(self):
        """
        Called when the module is disabled.
        Should be implemented.
        """
        pass


    def refresh_settings(self):
        """
        Called when the configurations are changed.
        Should be implemented.
        """
        pass


    def is_enabled(self):
        """ Returns True if the module is enabled """
        try:
            return self.options[InventoryConfig.module_enabled]
        except:
            return False


    def get_name(self):
        """
        Returns the name of the Module.
        Must be implemented.
        """
        raise ServerModule.NotImplemented('get_name')


    def init_default_settings(self):
        """
        Sets in the self.options dictionary the default settings for this
        module.
        Should be implemented.
        """
        pass


    def init_database_operations(self):
        """
        Called by the Core when the Database is ready.
        The module should use this method to fetch the needed data from the
        database.
        Should be implemented.
        """
        pass


    def evaluate_request(self, request, data_connection):
        """
        Called when the Module receives a request trough the ServerInterface.
        request: The request received trough the ServerInterface. See
        umit.inventory.server.ServerInterface.Request and
        umit.inventory.server.ServerInterface.RequestFields for details.
        interface_connection: The connection on which the module must send
        his response. See umit.inventory.ServerInterface.InterfaceDataConnection
        for details.
        Should be implemented.
        """
        pass


    def shutdown(self):
        """
        Called when the Server is shutting down. The module should do
        any needed operations for closing down in this method.
        Should be implemented.
        """
        pass


    class NotImplemented(Exception):

        def __init__(self, name):
            self.err_msg = "Method " + str(name) + "() must be implemented!"

        def __str__(self):
            return repr(self.err_msg)



class ListenerServerModule:
    """ The interface for a ServerModule which listens for notifications """


    def listen(self):
        """
        Called when the module must start listening.

        The Module must call listenUDP/listenTCP/listenSSL on the default
        twisted reactor for all ports he wants to listen to.
        Should be implemented.
        """
        pass


    def get_protocol_name(self):
        """
        Return the name of the protocol used for this Listening Module.
        See umit.inventory.server.Notification.
        Must be implemented.
        """
        raise ServerModule.NotImplemented('get_protocol_name')



class SubscriberServerModule:
    """
    The interface for a ServerModule which subscribes for receiving
    notifications as they arrive to the ListenerServerModule's.
    """

    def receive_notification(self, notification):
        """
        Called when the module received a notification.

        Must be implemented.
        """
        raise ServerModule.NotImplemented('receive_notification')


    def subscribe(self):
        """
        Called when the module must subscribe to the listener modules from
        which he wants to receive notifications.

        Must be implemented.
        """
        raise ServerModule.NotImplemented('subscribe')
