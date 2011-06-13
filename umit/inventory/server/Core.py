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

import traceback
import json

from umit.inventory.server.Configs import ServerConfig
from umit.inventory.server.Module import ListenerServerModule
from umit.inventory.server.Module import SubscriberServerModule
from umit.inventory.server.Database import Database
from umit.inventory.common import CorruptInventoryModule
import umit.inventory.common
from umit.inventory.server.Notification import Notification

from twisted.internet import reactor


class ServerCore:

    def __init__(self, configs):
        self.configs = configs
        self.database = Database(configs)
        self.shell = ServerShell(self)
        self.database.shell = self.shell

        self.modules = []
        self._load_modules()


    def _load_modules(self):
        # Loads the modules as defined in the configuration file
        modules_names = self.configs.get_modules_list()

        for module_name in modules_names:
            if not self.configs.module_get_enable(module_name):
                continue
            try:
                module_path = self.configs.module_get_option(module_name,\
                        ServerConfig.module_path)
                module_obj = umit.inventory.common.load_module(module_name,\
                        module_path, self.configs, self.shell)

                # Do the object the get_name() sanity check
                try:
                    name = module_obj.get_name()
                except:
                    raise CorruptServerModule(module_name, module_path,\
                            CorruptServerModule.get_name)
                if name != module_name:
                    raise CorruptServerModule(module_name, module_path,\
                            CorruptServerModule.get_name)

            except Exception, e:
                traceback.print_exc()
                continue
            self.modules.append(module_obj)

        # Init subscriptions. This is done now because all modules must be
        # loaded and initialized before the subscribtions are done.
        for module in self.modules:
            if isinstance(module, SubscriberServerModule):
                module.subscribe()

        # Init the database operations for each module.
        for module in self.modules:
            module.init_database_operations()


    def run(self):
        """ The server main loop. """
        # Call the modules which implement ListenerServerModule so they
        # will start listening.
        for module in self.modules:
            if isinstance(module, ListenerServerModule):
                module.listen()

        reactor.run()



class CorruptServerModule(CorruptInventoryModule):

    get_name = 2

    def __init__(self, module_name, module_path, err_type=0):
        CorruptInventoryModule.__init__(self, module_name,\
                module_path, err_type)
        if err_type == CorruptServerModule.get_name:
            self.err_description = module_name + 'doesn\'t implement' +\
                    'the get_name() method or it\'s return value is incorrect'



class ServerShell:
    """
    Used to provide an interface to the Notifications Server internals.
    It provides methods so modules can subscribe to notifications, so they
    will receive real-time notifications and also methods to allow the modules
    to query the database.
    """

    def __init__(self, core):
        self._core = core
        self.database = self._core.database
        self._subscriptions = dict()


    def get_modules_list(self):
        """ Returns the list with all the modules installed. """
        return self._core.modules


    def subscribe(self, subscriber, listener_name='', subscribe_all=True):
        """
        The subscriber will be signaled when a ListenerServerModule receives
        a notification.

        subscriber: A SubscriberServerModule object.
        listener_name: The name of the listener module we should subscribe to.
        It's used only if subscribe_all is False.
        subscribe_all: If it should subscribe to all the listener modules.
        If False, then listener_name should be different from ''.
        """
        if not isinstance(subscriber, SubscriberServerModule):
            raise InvalidSubscriber(subscriber)

        if subscribe_all:
            for module in self._core.modules:
                # Only interested in subscribing to listener modules.
                if not isinstance(module, ListenerServerModule):
                    continue

                # If no one subscribed to this listener module until now, then
                # add it to the dictionary.
                module_name = module.get_name()
                if module_name not in self._subscriptions.keys():
                    self._subscriptions[module_name] = []

                self._subscriptions[module_name].append(subscriber)
            return

        # Similar to above. First subscriber to subscribe to this module.
        if listener_name not in self.subscriptions.keys():
            self._subscriptions[listener_name]
        self._subscriptions[listener_name].append(subscriber)


    def parse_notification(self, listener_name, notification):
        """
        Called by the ListenerServerModule objects after they received
        a notification. All the modules which subscribed will have the
        receive_notification() method called with notification as
        argumment.

        listener_name: The name of the listener module which received the
        notification.
        notification: The actual notification.
        """
        self.database.store_notification(notification)

        # No one subscribed to this listener.
        if listener_name not in self._subscriptions.keys():
            return

        for module in self._subscriptions[listener_name]:
            if not isinstance(module, SubscriberServerModule):
                raise InvalidSubscriber(module)

            module.receive_notification(notification)


    class InvalidSubscriber(Exception):

        def __init__(self, subscriber):
            self.err_msg = str(subscriber)

        def __str__(self):
            return repr(self.err_msg)
