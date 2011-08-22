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

import logging
import json
import time
from threading import Lock

from umit.inventory.server.Configs import ServerConfig
from umit.inventory.server.Module import ListenerServerModule
from umit.inventory.server.Module import SubscriberServerModule
from umit.inventory.server.Database import Database
from umit.inventory.server.ServerInterface import ServerInterface
from umit.inventory.server.UserSystem import UserSystem
from umit.inventory.common import CorruptInventoryModule
from umit.inventory.server.Notification import Notification
from umit.inventory.server.Notification import NotificationFields
import umit.inventory.common
from umit.inventory.Configuration import InventoryConfig

from twisted.internet import reactor


class ServerCore:

    def __init__(self, configs):
        logging.info('Initializing ServerCore ...')

        self.initialized = True
        self.configs = configs
        try:
            self.database = Database(configs)
        except:
            logging.critical('Failed to initialize ServerCore. Shutting down.',
                             exc_info=True)
            self.initialized = False
            return
        
        if self.database.database is None:
            logging.critical('Failed to initialize ServerCore. Shutting down.')
            self.initialized = False
            return
        self.shell = ServerShell(self)
        self.database.shell = self.shell

        self.modules = {}
        self._load_modules()
        
        self.user_system = UserSystem(self.database)
        self.server_interface = ServerInterface(self.configs,
                                                self.user_system, self.shell)
        self.shell.server_interface = self.server_interface

        # Initialize the Notification system
        Notification.registered_classes[Notification.get_name()] = Notification

        # Save the configs
        self.configs.save_settings()

        logging.info('Initialized ServerCore')


    def set_admin_password(self, password):
        if not self.initialized:
            return False
        self.user_system.set_admin_password(password)
        return True


    def _load_modules(self):
        logging.info('Loading modules ...')
        modules_objects =\
            umit.inventory.common.load_modules_from_target('server',
                self.configs, self.shell)
        for module_object in modules_objects:
            self.modules[module_object.get_name()] = module_object
        logging.info('Loaded modules')


    def _activate_modules(self):
        # Init subscriptions. This is done now because all modules must be
        # loaded and initialized before the subscribtions are done.
        logging.info('Initializing modules subscriptions ...')
        for module in self.modules.values():
            if not module.is_enabled():
                continue
            if isinstance(module, SubscriberServerModule):
                module.subscribe()
        logging.info('Initialized modules subscriptions.')

        # Init the database operations for each module.
        logging.info('Initializing modules database operations ...')
        for module in self.modules.values():
            module.init_database_operations()
        logging.info('Done initializing modules database operations.')

        # Activate the modules
        logging.info('Activating modules ...')
        for module in self.modules.values():
            if module.is_enabled():
                module.activate()
        logging.info('Done activating modules.')


    def update_configs(self, configs):
        try:
            logging.info('Updating configurations.\n%s',
                         json.dumps(configs, sort_keys=True, indent=4))
        except:
            logging.warning('Invalid configuration change request',
                            exc_info=True)

        try:
            sections = configs.keys()
            for section in sections:
                options = configs[section]
                for option_name in options.keys():
                    option_value = options[option_name]
                    self.configs.set(section, option_name, option_value)

                # If a module, refresh it's settings and activate if needed
                if section in self.modules.keys():
                    module = self.modules[section]
                    if not module.is_enabled() and\
                       self.configs.get(section, InventoryConfig.module_enabled):
                        module.activate()
                    module.refresh_settings()

            # Save the settings
            self.configs.save_settings()
        except:
            logging.error('Changing server configurations failed',
                          exc_info=True)


    def run(self):
        if not self.initialized:
            return
        
        self._activate_modules()

        # Call the modules which implement ListenerServerModule so they
        # will start listening.
        for module in self.modules.values():
            if not module.is_enabled():
                continue
            if isinstance(module, ListenerServerModule):
                module.listen()
        self.server_interface.listen()
        
        logging.info('Starting the Twisted Reactor')
        reactor.run()


    def shutdown(self):
        for module in self.modules.values():
            if module.is_enabled():
                module.deactivate()
            module.shutdown()
        reactor.stop()



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
        self.server_interface = None
        self.raise_notification_lock = Lock()
        self._full_subscribers = []
        self._subscriptions = dict()
        logging.info('Initialized ServerShell')


    def get_modules_list(self):
        """ Returns the list with all the modules installed. """
        return self._core.modules.values()


    def get_modules_names_list(self):
        """ Returns the list all the modules names installed. """
        return self._core.modules.keys()


    def get_module(self, module_name):
        """ Returns the module with the given name or None """
        if module_name in self._core.modules.keys():
            return self._core.modules[module_name]
        return None


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
            for module in self._core.modules.values():
                # Only interested in subscribing to listener modules.
                if not isinstance(module, ListenerServerModule):
                    continue

                # If no one subscribed to this listener module until now, then
                # add it to the dictionary.
                module_name = module.get_name()
                if module_name not in self._subscriptions.keys():
                    self._subscriptions[module_name] = []

                self._subscriptions[module_name].append(subscriber)
            self._full_subscribers.append(subscriber)
            logging.info('Module %s subscribed to all listener modules',\
                         subscriber.get_name())
            return

        # Similar to above. First subscriber to subscribe to this module.
        if listener_name not in self._subscriptions.keys():
            self._subscriptions[listener_name] = [subscriber]
        self._subscriptions[listener_name].append(subscriber)
        logging.info('Module %s subscribed to %s', subscriber.get_name(),\
                     listener_name)


    def parse_notification(self, listener_name, notification):
        """
        Called by the ListenerServerModule objects after they received
        a notification. All the modules which subscribed will have the
        receive_notification() method called with notification as
        argument.

        listener_name: The name of the listener module which received the
        notification.
        notification: The actual notification (a Notification object).
        """
        self.database.store_notification(notification)
        self.server_interface.forward_notification(notification)

        # No one subscribed to this listener.
        if listener_name not in self._subscriptions.keys():
            return

        for module in self._subscriptions[listener_name]:
            if not isinstance(module, SubscriberServerModule):
                raise InvalidSubscriber(module)

            module.receive_notification(notification)


    def raise_notification(self, description, short_description, notif_type,\
                           is_report=False, ipv4_addr='', ipv6_addr='',\
                           hostname=''):
        """
        Used to raise a internal server notification.
        """
        self.raise_notification_lock.acquire()
        # Construct the notification
        notif_fields = dict()
        notif_fields[NotificationFields.description] = unicode(description)
        notif_fields[NotificationFields.short_description] = unicode(short_description)
        notif_fields[NotificationFields.notification_type] = str(notif_type)
        notif_fields[NotificationFields.is_report] = is_report
        notif_fields[NotificationFields.hostname] = str(hostname)
        notif_fields[NotificationFields.timestamp] = time.time()
        notif_fields[NotificationFields.protocol] = 'UmitAgent'
        notif_fields[NotificationFields.source_host_ipv4] = str(ipv4_addr)
        notif_fields[NotificationFields.source_host_ipv6] = str(ipv6_addr)

        notification = Notification(notif_fields)
        self.database.store_notification(notification)
        self.server_interface.forward_notification(notification)
        for subscriber in self._full_subscribers:
            subscriber.receive_notification(notification)
        self.raise_notification_lock.release()


    def update_configs(self, configs):
        """
        Updates the server configurations.
        configs: A dictionary with keys having section names and as values
        dictionaries with (option_name, option_value) entries.
        """
        self._core.update_configs(configs)


class InvalidSubscriber(Exception):

    def __init__(self, subscriber):
        self.err_msg = str(subscriber)

    def __str__(self):
        return repr(self.err_msg)
