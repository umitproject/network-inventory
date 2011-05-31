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


class MongoDatabase(ServerModule, SubscriberServerModule):
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

    # Config options
    host = 'host'
    port = 'port'
    database_name = 'database_name'
    notifications_collection = 'notification_collection'
    username = 'username'
    password = 'password'


    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)

        self.host = str(self.options[MongoDatabase.host])
        self.port = str(self.options[MongoDatabase.port])
        self.database_name = str(self.options[MongoDatabase.database_name])
        self.notifications_collection_name =\
                str(self.options[MongoDatabase.notifications_collection])
        self.username = str(self.options[MongoDatabase.username])
        self.password = str(self.options[MongoDatabase.password])

        self.connection = None
        self.database = None
        try:
            self._connect()
        except Exception, e:
            # TODO log this
            traceback.print_exc()

        # If we failed to load the database.
        if self.database == None:
            return

        self.notifications_collection =\
                self.database[self.notifications_collection_name]


    def get_name(self):
        return 'MongoDatabase'


    def subscribe(self):
        # We will subscribe to all the listener modules.
        self.shell.subscribe(self)


    def init_default_settings(self):
        self.options[MongoDatabase.host] = 'localhost'
        self.options[MongoDatabase.port] = ''
        self.options[MongoDatabase.database_name] = 'umit_inventory'
        self.options[MongoDatabase.notifications_collection] = 'notitifications'
        self.options[MongoDatabase.username] = ''
        self.options[MongoDatabase.password] = ''


    def receive_notification(self, notification):
        """ Called when a notification was received """
        #TODO: Store the notification
        print '-----------------------------'
        print notification.encode()

        if not isinstance(notification, Notification):
            # TODO maybe log this
            return

        self.notifications_collection.insert(notification.encode())


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

