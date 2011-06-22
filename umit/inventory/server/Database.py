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

import pymongo

from umit.inventory.server.Module import ServerModule
from umit.inventory.server.Module import SubscriberServerModule
from umit.inventory.server.Notification import Notification

import traceback
from copy import copy

class Database:
    """
    The standard implementation of the Notifications Server database.

    Will listen trough the Shell to the notifications received and store
    them as configured.

    If interested in writting a new database feature for the Notifications
    Server, you can start from here. See:
        umit.inventory.server.Module.ServerModule
        umit.inventory.server.Core.ServerShell.subscribe()

    General options:
        database_name: The name of the database.
        notifications_collection: The name of the collection where the
        notifications are stored.
        username: The username for the database. If equal to '', then no
        authentication is required.
        password: If the username is not '', then the password to
        authenticate to the database.
    """

    # The name of the configuration section
    config_section_name = 'Database'

    # Config options
    host = 'host'
    port = 'port'
    database_name = 'database_name'
    notifications_collection = 'notification_collection'
    username = 'username'
    password = 'password'
    store_notifications = 'store_notifications'


    def __init__(self, configs):
        self.configs = configs

        self.notifications_collection = None
        self._init_default_settings()
        self._load_settings(configs)

        # Get the options
        self.host = str(self.options[Database.host])
        self.port = str(self.options[Database.port])
        self.database_name = str(self.options[Database.database_name])
        self.notifications_collection_name =\
                str(self.options[Database.notifications_collection])
        self.username = str(self.options[Database.username])
        self.password = str(self.options[Database.password])
        self.store_notifications =\
                bool(self.options[Database.store_notifications])

        # Try to connect to the dabatase
        self.connection = None
        self.database = None
        try:
            self._connect()
        except Exception, e:
            # TODO log this
            traceback.print_exc()

        # If we failed to connect to the database.
        if self.database == None:
            return

        # The collection where the notifications will be stored (if configured
        # as such).
        self.notifications_collection =\
                self.database[self.notifications_collection_name]



    def store_notification(self, notification):
        """ Called when a notification was received """
        # If we shouldn't store the notifications
        if not self.store_notifications:
            return

        # Make sure we succcesfully connected to the db
        if self.database == None:
            return

        print '--------- STORING -----------'
        print notification.fields
        print '-----------------------------'

        if not isinstance(notification, Notification):
            return

        # Saving a copy since mongodb will add the ObjectID to the dictionary
        # which won't keep it JSON seriazable
        self.notifications_collection.insert(copy(notification.fields))


    # Mongo wrappers

    def insert(self, collection_name, database_object):
        """
        Stores the given object to the given collection.

        collection_name: The name of the collection where the object should
        be inserted.
        database_object: A dict with entries 'field_name : field_value'
        """
        self.database[collection_name].insert(database_object)


    def find(self, collection_name, search_spec=None, returned_fields=None,\
            sorted_fields=None):
        """
        Searches the database.
        search_spec: A dictionary with entries field_name : field_value to
        specify the returned values.
        returned_fields: A list of field names to be included in the returned
        results.
        sorted_fields: A list of (field_name, direction) to sort the results.
        direction should be True for ascending sort and False for descending.
        """
        if sorted_fields != None:
            for entry in sorted_fields:
                entry[1] = pymongo.ASCENDING if entry[1] else\
                           pymongo.DESCENDING

        return self.database[collection_name].find(spec=search_spec,\
                fields=returned_fields, sort=sorted_fields)


    # Private methods

    def _init_default_settings(self):
        self.options = dict()

        self.options[Database.host] = 'localhost'
        self.options[Database.port] = ''
        self.options[Database.database_name] = 'umit_inventory'
        self.options[Database.notifications_collection] = 'notifications'
        self.options[Database.username] = ''
        self.options[Database.password] = ''
        self.options[Database.store_notifications] = 'True'


    def _load_settings(self, configs):
        """ Gets the settings from the configs in self.options. """
        if not configs.has_section(Database.config_section_name):
            return

        options_names = configs.options(Database.config_section_name)

        for option_name in options_names:
            self.options[option_name] =\
                    configs.get(Database.config_section_name, option_name)


    def _connect(self):
        """ Connects to the database as configured """

        # Initialize the host string considering username/password (if present)
        auth_string = self.username + ':' + self.password + '@'
        host_string = auth_string if self.username != '' else ''
        host_string += self.host

        if self.port != '':
            self.connection = pymongo.Connection(host_string, int(self.port))
        else:
            self.connection = pymongo.Connection(host_string)

        self.database = self.connection[self.database_name]

