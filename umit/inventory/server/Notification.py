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
from copy import copy

class Notification:
    """
    Unified notification format that will be saved in the database. Every
    listener module must convert their notifications in this format to
    be stored in the database.

    Only notifications objects which are instances of this class will be
    accepted to be stored in the database.

    Standard fields:
    * source_host: The host that generated the notification.
    * timestamp: When the notification was generated. Should be a float similar
      to the one obtained by time().
    * protocol: The name of the protocol used by the listener. E.g. SNMP,
      UmitAgent, etc.
    * type: The type of the notification. See
      umit.inventory.common.NotificationTypes.
    * description: A short description of the notification.
      that is JSON seriazable.
    """

    def __init__(self, fields):
        """
        Initializes a notification message.
        fields: A dictionary with all the fields in this entry. It can contain
        any fields, but must contain the Notification class specific ones.
        """

        # Ensure the fields are json seriazable
        json.dumps(fields)

        # Perform the fields sanity check
        try:
            self.source_host = fields[NotificationFields.source_host]
        except:
            raise MissingNotificationFields(NotificationFields.source_host)

        try:
            self.timestamp = fields[NotificationFields.timestamp]
        except:
            raise MissingNotificationFields(NotificationFields.timestamp)

        try:
            self.protocol = fields[NotificationFields.protocol]
        except:
            raise MissingNotificationFields(NotificationFields.protocol)

        try:
            self.type = fields[NotificationFields.type]
        except:
            raise MissingNotificationFields(NotificationFields.type)

        try:
            self.description = fields[NotificationFields.description]
        except:
            raise MissingNotificationFields(NotificationFields.description)

        # Save the fields dictionary to ensure additional fields are not lost.
        self.fields = fields


    def encode(self):
        """
        Encodes the current Notification to an object that can be stored in the
        database. Returns that object. Should be used only by the database
        before storing the notification.
        """
        return self.fields


    @staticmethod
    def decode(db_obj):
        """
        Used by the database to decode the DB object into this class format.
        Basically, message == Notification.decode(message.encode()).
        """
        # Sanity check will be performed in the Notification constructor
        return Notification(db_obj)



class NotificationFields:

    source_host = 'source_host'
    timestamp = 'timestamp'
    protocol = 'protocol'
    type = 'type'
    description = 'description'



class MissingNotificationFields(Exception):

    def __init__(self, field_name):
        self.err_msg = 'Field + ' + str(field_name) + ' is mandatory'

    def __str__(self):
        return repr(self.err_msg)
