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

    * source_host_ipv4: Source host IPv4 (or '' if not defined).
    * source_host_ipv6: Source host IPv6 (or '' if not defined).
    * hostname: Source host name (or '' if not defined)
    * timestamp: The number of seconds since the epoch when the notification
      was generated.
    * protocol: The name of the protocol which generated the notification. E.g.
      SNMP, UmitAgent, etc.
    * fields_class: The name of the class that defines the fields included in
      the notification.
    * notification_type: The type of the notification. E.g. WARNING, CRITICAL,
      INFO, etc.
    * is_report: True if it's a report sent from a fixed time by the host. This
      indicates that the notification shouldn't be treated as an alarm.
    * description: A detailed description of the notification.
    * short_description: A short description of the notification (maximum
      160 chars)

    For the types of these fields, see NotificationFields. The values of these
    fields can be found in the object property fields which is a dictionary
    having as keys the names defined in NotificationFields.
    """

    # Registered notifications classes
    registered_classes = {}

    def __init__(self, fields, clean=True):
        """
        Initializes a notification message.
        fields: A dictionary with all the fields in this entry. It can contain
        any fields, but must contain the Notification class specific ones and
        also have the correct type (see NotificationFields class).
        clean: If True, non-JSON seriazable fields will be removed.
        """

        # Save the fields and check they are correct
        self.fields = fields
        self.fields[NotificationFields.fields_class] = self.get_name()

        if clean:
            self._clean()
        self.sanity_check()


    def _clean(self):
        """
        Prepares a notification for JSON serialization by removing
        non-seriazable fields
        """
        new_fields = dict()
        for field_key in self.fields.keys():
            try:
                json.dumps(self.fields[field_key])
                json.dumps(field_key)
                new_fields[field_key] = self.fields[field_key]
            except:
                continue
        self.fields = new_fields

    
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
                # Accepting unicode and str as same types
                if type(self.fields[name]) and types[name] in [unicode, str]:
                    continue
                
                raise IncorrectNotificationFieldType(name,\
                        type(self.fields[name]), types[name], self.get_name())


    @staticmethod
    def get_name():
        """
        Returns the name of the class.
        Must be implemented when inheriting.
        """
        return 'BaseNotification'


    @staticmethod
    def get_fields_class():
        """
        Returns a class which inherents or is NotificationFields.
        See the documentation of the NotificationFields class for details.
        """
        return NotificationFields


    @staticmethod
    def register_class(notification_class):
        Notification.registered_classes[notification_class.get_name()] =\
                notification_class



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
    is_report = 'is_report'
    description = 'description'
    short_description = 'short_description'
    names = [source_host_ipv4, source_host_ipv6, hostname, timestamp, protocol,\
             fields_class, notification_type, is_report, description,\
             short_description]

    # The notification fields types.
    types = dict()
    types[source_host_ipv4] = str
    types[source_host_ipv6] = str
    types[hostname] = str
    types[timestamp] = float
    types[protocol] = str
    types[fields_class] = str
    types[notification_type] = str
    types[is_report] = bool
    types[description] = unicode
    types[short_description] = unicode


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
        self.err_msg = 'Field %s has type %s for class %s. Expected %s.' %\
                (field_name, str(field_crt_type), notification_class_name,\
                 str(field_correct_type))

    def __str__(self):
        return repr(self.err_msg)

