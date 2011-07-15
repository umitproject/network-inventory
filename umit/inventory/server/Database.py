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

from umit.inventory.server.Notification import Notification
from umit.inventory.server.Notification import NotificationFields
from umit.inventory.server.Host import Host

import logging
import json
from copy import copy
from threading import Lock


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
    notifications_collection = 'notifications_collection'
    hosts_collection = 'hosts_collection'
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
        self.hosts_collection_name =\
                str(self.options[Database.hosts_collection])
        self.username = str(self.options[Database.username])
        self.password = str(self.options[Database.password])
        self.store_notifications =\
                bool(self.options[Database.store_notifications])

        # Try to connect to the dabatase
        self.connection = None
        self.database = None
        try:
            logging.info('Trying to connect to the database ...')
            self._connect()
            logging.info('Successfully connected to the database.')
        except Exception, e:
            critical_msg = 'Failed to load database. Shutting down.\n'
            critical_msg += 'Make sure you have MongoDatabase installed and '
            critical_msg += 'that the mongod daemon is running.\n'
            critical_msg += 'Database Name: %s\n' % self.database_name
            critical_msg += 'Database Host: %s\n' % self.host
            if self.port == '':
                critical_msg += 'Database Port: [Default mongodb port]'
            else:
                critical_msg += 'Databse Port: %s' % self.port
            logging.critical(critical_msg, exc_info=True)
            return

        # The collection where the notifications will be stored (if configured
        # as such).
        self.notifications_collection =\
                self.database[self.notifications_collection_name]

        # The collection where the hosts will be stored
        self.hosts_collection = self.database[self.hosts_collection_name]
        self.hosts_collection_lock = Lock()


    def get_notifications_collection_name(self):
        return self.notifications_collection_name


    def get_hosts_collection_name(self):
        return self.hosts_collection_name


    def store_notification(self, notification):
        """ Called when a notification was received """
        # If we shouldn't store the notifications
        if not self.store_notifications:
            return

        # Make sure we successfully connected to the db
        if self.database is None:
            return

        if not isinstance(notification, Notification):
            logging.debug('%s is not of Notification class',\
                          notification.fields)
            return

        logging.debug('############# STORING #########\n%s',\
                      json.dumps(notification.fields, sort_keys=True, indent=4))

        # Saving a copy since mongodb will add the ObjectID to the dictionary
        # which won't keep it JSON seriazable
        self.notifications_collection.insert(copy(notification.fields))


    # Host querying method

    def add_host(self, host):
        """
        Adds the host to the database.
        host: A Host object.
        """
        self.hosts_collection_lock.acquire()

        if self.find(self.hosts_collection_name,\
                     {Host.hostname : host.hostname}).count() == 1:
            self.update(self.hosts_collection_name,\
                        {Host.hostname : host.hostname},\
                        {Host.ipv4_addr : host.ipv4_addr,\
                         Host.ipv6_addr : host.ipv6_addr})
        else:
            self.insert(self.hosts_collection_name, host.to_db_object())
        self.hosts_collection_lock.release()


    def get_hosts(self):
        """ Gets a list with all the hosts in the database """
        self.hosts_collection_lock.acquire()
        host_list = self.find(self.hosts_collection_name)
        self.hosts_collection_lock.release()

        hosts = list()
        for host_db_obj in host_list:
            hosts.append(Host.from_db_object(host_db_obj))
        return hosts


    def get_host(self, hostname):
        """ Get the host object with the given hostname """
        self.hosts_collection_lock.acquire()
        host_list = self.find(self.hosts_collection_name,\
                              {Host.hostname : hostname})
        self.hosts_collection_lock.release()
        if type(host_list) is list:
            return Host.from_db_object(host_list[0])
        return None


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
            sorted_fields=None, tailable=False):
        """
        Searches the database.
        search_spec: A dictionary with entries field_name : field_value to
        specify the returned values.
        returned_fields: A list of field names to be included in the returned
        results.
        sorted_fields: A list of (field_name, direction) to sort the results.
        direction should be True for ascending sort and False for descending.
        tailable: See MongoDB tailable option for the find method. Will return
        a tailable cursor.
        """
        if sorted_fields is not None:
            for entry in sorted_fields:
                entry[1] = pymongo.ASCENDING if entry[1] else\
                           pymongo.DESCENDING

        return self.database[collection_name].find(spec=search_spec,\
                fields=returned_fields, sort=sorted_fields, tailable=tailable)


    def update(self, collection_name, spec_fields, updated_fields):
        """
        Updates a document (or more) in the given collection.
        spec_fields: A dict specifying the values for the fields to match
        the documents to be updated.
        updated_fields: A dict with the new values for the fields specified
        as keys.
        """
        self.database[collection_name].update(spec_fields, updated_fields)


    def remove(self, collection_name, spec_fields=None):
        """
        Removes a document (or more) from the given collection.
        spec_fields: A dict specifying the values for the fields to match
        the documents to be removed. If None, all the documents from the
        collection will be removed.
        """
        self.database[collection_name].remove(spec_fields)


    def ensure_index(self, collection_name, key_or_list, unique_key=False,\
                     background_exec=False):
        """
        Ensures an index on a field or list of fields in the given collection.
        key_or_list: A key or a list of keys that should be indexed.
        unique_key: If the index should provide uniqueness for the key.
        background_exec: If the operation should be executed in background.
        """
        self.database[collection_name].ensure_index(key_or_list,\
                                unique=unique_key, background=background_exec)




    # Private methods

    def _init_default_settings(self):
        self.options = dict()

        self.options[Database.host] = 'localhost'
        self.options[Database.port] = ''
        self.options[Database.database_name] = 'umit_inventory'
        self.options[Database.notifications_collection] = 'notifications'
        self.options[Database.hosts_collection] = 'hosts'
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
