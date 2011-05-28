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
    * custom_fields: Custom fields for this notification. It should be a dictionary
      that is JSON seriazable.
    """

    def __init__(self, standard_fields, custom_fields=None):
        """ Initializes a notification message. """

        # Perform the fields sanity check
        try:
            self.source_host = standard_fields[NotificationFields.source_host]
        except:
            raise MissingNotificationFields(NotificationFields.source_host)

        try:
            self.timestamp = standard_fields[NotificationFields.timestamp]
        except:
            raise MissingNotificationFields(NotificationFields.timestamp)

        try:
            self.protocol = standard_fields[NotificationFields.protocol]
        except:
            raise MissingNotificationFields(NotificationFields.protocol)

        try:
            self.type = standard_fields[NotificationFields.type]
        except:
            raise MissingNotificationFields(NotificationFields.type)

        try:
            self.description = standard_fields[NotificationFields.description]
        except:
            raise MissingNotificationFields(NotificationFields.description)

        # If there are custom fields, check if they are valid and add them.
        if custom_fields != None:
            # Check if it's JSON seriazable.
            try:
                temp = json.dumps(custom_fields)
                self.custom_fields = custom_fields
            except:
                raise CorruptCustom(custom_fields)
        else:
            self.custom_fields = dict()


    def encode(self):
        """
        Encodes the current Notification to an object that can be stored in the
        database. Returns that object. Should be used only by the database
        before storing the notification.
        """
        db_obj = dict()
        db_obj[NotificationFields.source_host] = self.source_host
        db_obj[NotificationFields.timestamp] = self.timestamp
        db_obj[NotificationFields.protocol] = self.protocol
        db_obj[NotificationFields.type] = self.type
        db_obj[NotificationFields.description] = self.description
        db_obj[NotificationFields.custom_fields] = self.custom_fields

        return db_obj


    @staticmethod
    def decode(db_obj):
        """
        Used by the database to decode the DB object into this class format.
        Basically, message == Notification.decode(message.encode()).
        """
        # Sanity check on the db_obj

        # Check if it's JSON seriazable
        temp = json.dumps()

        # Check if it has the custom_fields field
        try:
            custom_fields = db_obj[NotificationFields.custom_fields]
        except:
            raise MissingNotificationFields(NotificationFields.custom_fields)

        return Notification(db_obj, custom_fields)



class NotificationFields:

    source_host = 'source_host'
    timestamp = 'timestamp'
    protocol = 'protocol'
    type = 'type'
    description = 'description'
    custom_fields = 'custom_fields'



class MissingNotificationFields(Exception):

    def __init__(self, field_name):
        self.err_msg = 'Field + ' + str(field_name) + ' is mandatory'

    def __str__(self):
        return repr(self.err_msg)



class CorruptCustom(Exception):

    def __init__(self, custom_fields):
        self.err_msg = str(custom_fields) + ' is invalid (not JSON seriazable).'

    def __str__(self):
        return repr(self.err_msg)

