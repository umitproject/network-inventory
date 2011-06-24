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
    * fields_class: The name of the class that defines the fields for the
      notification. Should NOT be added manually.
    * notification_type: The type of the notification. See
      umit.inventory.common.NotificationTypes.
    * description: A short description of the notification.

    For the types of these fields, see NotificationFields. The values of these
    fields can be found in the object property fields which is a dictionary
    having as keys the names defined in NotificationFields.
    """

    def __init__(self, fields):
        """
        Initializes a notification message.
        fields: A dictionary with all the fields in this entry. It can contain
        any fields, but must contain the Notification class specific ones and
        also have the correct type (see NotificationFields class).
        """

        # Save the fields and check they are correct
        self.fields = fields
        self.sanity_check()

        self.fields[NotificationFields.fields_class] = self.get_name()


    def sanity_check(self):
        """ Ensure the correct names and types in the fields """
        fields_class = self.get_fields_class()

        names = fields_class.get_names()
        types = fields_class.get_types()

        for name in names:
            # Check the name exists in the fields
            if name not in self.fields.keys():
                raise MissingNotificationField(name, self.get_name())

            # Check it has the correct type
            if type(self.fields[name]) != types[name]:
                raise IncorrectNotificationFieldType(name,\
                        type(self.fields[name]), types[name], self.get_name())


    def get_name(self):
        """
        Returns the name of the class.
        Must be implemented when inheriting.
        """
        return 'BaseNotification'


    def get_fields_class(self):
        """
        Returns a class which inherents or is NotificationFields.
        See the documentation of the NotificationFields class for details.
        """
        return NotificationFields



class NotificationFields:
    """
    Class defining the fields of a Notification and their types.

    For every class that inherents the base Notification class you must
    define a class that inherents the NotificationFields class which
    implements a get_names() and get_types() methods.

    The get_names()/get_types() methods must return a names list/types dict
    which adds the new Notification fields, but it's mandatory it copies
    the names/types from this class (or it's nearest ancestor).
    """

    # If adding a field, you must:
    # 1. Assign it's string value to a variable for easier referencing.
    # 2. Add the variable to the names list.
    # 3. Associate it's type in the types dictionary.

    # The notification fields names.
    source_host_ipv4 = 'source_host_ipv4'
    source_host_ipv6 = 'source_host_ipv6'
    hostname = 'hostname'
    timestamp = 'timestamp'
    protocol = 'protocol'
    fields_class = 'fields_class'
    notification_type = 'event_type'
    description = 'description'
    names = [source_host_ipv4, source_host_ipv6, timestamp, protocol,\
             notification_type, description]

    # The notification fields types.
    types = dict()
    types[source_host_ipv4] = str
    types[source_host_ipv6] = str
    types[timestamp] = float
    types[protocol] = str
    types[fields_class] = str
    types[notification_type] = str
    types[description] = unicode


    @staticmethod
    def get_names():
        return NotificationFields.names


    @staticmethod
    def get_types():
        return NotificationFields.types



class MissingNotificationField(Exception):

    def __init__(self, field_name, notification_class_name):
        self.err_msg = 'Field %s is mandatory for notification class %s' %\
                (field_name, notification_class_name)

    def __str__(self):
        return repr(self.err_msg)


class IncorrectNotificationFieldType(Exception):

    def __init__(self, field_name, field_crt_type, field_correct_type,\
            notification_class_name):
        self.err_msg = 'Field %s got type %s for class %s. Expected %s.' %\
                (field_name, str(field_crt_type), notification_class_name,\
                 str(field_correct_type))

    def __str__(self):
        return repr(self.err_msg)

