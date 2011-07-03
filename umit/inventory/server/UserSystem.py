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

import hashlib
import logging


class UserSystem:

    # The collection where the user information is saved
    collection_name = 'user_system_users'


    def __init__(self, database):
        self.database = database
        self.users = dict()

        users_temp = self.database.find(UserSystem.collection_name)
        for user in users_temp:
            self.users[user[User.username]] = User(user[User.username],\
                    UserPermissions.deserialize(user[User.permissions]),\
                    md5_password=user[User.md5_pass])


    def get_user(self, username):
        """ Returns the User object for the username or None """
        if username in self.users:
            return self.users[username]
        return None


    def add_user(self, username, password, permissions):
        if username in self.users.keys():
            return False

        # Add to internal dict
        user_obj = User(username, permissions, password=password)
        self.users[username] = user_obj

        # Add to database
        self.database.insert(user_obj.serialize())


    def del_user(self, username):
        # Delete from database
        self.database.remove({User.username : username})

        # Delete from internal dict
        if username not in self.users.keys():
            return
        del self.users[username]


    def set_user(self, username, password=None, permissions=None):
        if username not in self.users.keys():
            raise Exception('Username %s not in User System' % username)
        user_obj = self.users[username]
        updated_fields = dict()

        if password is not None:
            user_obj.set_password(password)
            updated_fields[User.md5_pass] = user_obj.md5_password

        if permissions is not None:
            user_obj.permissions = permissions
            updated_fields[User.permissions] = permissions

        # If we actually updated password/permissions or both
        if len(updated_fields) > 0:
            self.database.update(UserSystem.collection_name,
                                 {User.username : username}, updated_fields)


    def validate_user(self, username, password):
        # Check the username is registered
        if username not in self.users.keys():
            raise FailedUserValidation('Username %s not in User System'\
                                       % username)

        # Check's if the password is correct
        user_obj = self.users[username]
        if not user_obj.check_password(password):
            raise FailedUserValidation('Wrong password for user %s' % username)



class User:
    """ A user in the Server User System """

    # Database fields
    username = 'username'
    md5_pass = 'md5_pass'
    permissions = 'permissions'


    def __init__(self, username, permissions, md5_password=None, password=None):
        """
        Either md5_password or password must be given. If both are given, then the
        md5 encoded one will have priority.
        If
        """
        self.username = username
        self.permissions = permissions

        # Store the password for the user as an MD5 digest
        if md5_password is None and password is None:
            raise Exception('md5_password or password required in constructor')
        if md5_password is not None:
            self.md5_password = md5_password
        else:
            self.set_password(password)


    def set_password(self, password):
        self.md5_password = hashlib.md5(password).hexdigest()


    def check_password(self, password):
        """
        Checks if the password argument matches with the password for this
        user.
        Returns True if it's matches, False otherwise.
        """
        return hashlib.md5(password).hexdigest() == self.md5_password


    def can_manage_users(self):
        """ Check if the user has the permission to manage other users """
        return self.permissions.manage_users


    def can_restart_server(self):
        """ Checks if the user has the permission to restart the server """
        return self.permissions.restart_server


    def can_get_configs(self):
        """ Checks if the user has the permission to get the configurations """
        return self.permissions.get_configs


    def can_set_configs(self):
        """ Checks if the user has the permission to set the configurations """
        return self.permissions.set_configs


    def get_permitted_hosts(self, hosts):
        """
        Returns a list with the hosts has permission to access from the given
        hosts list.
        """
        #TODO
        return hosts


    def serialize(self):
        serialized_obj = dict()
        serialized_obj[User.username] = self.username
        serialized_obj[User.md5_pass] = self.md5_password
        serialized_obj[User.permissions] = self.permissions.serialize()
        return serialized_obj


    @staticmethod
    def deserialize(self, db_object):
        return User(db_object[User.username],\
                    UserPermissions.deserialize(db_object[User.permissions]),\
                    md5_password=db_object[User.md5_pass])

        

class UserPermissions:
    """
    User permissions:
    * manage_users: bool. If the user can manage the other users (add, delete,
      change permissions, change their passwords). The user will always be able
      to change it's own password, regardless of the permissions.
    * restart_server: bool. If the user can request a restart of the server.
    * get_configs: bool. If the user can get the current configurations of the
      server.
    * set_configs: bool. If the user can set the configurations of the server.
    * hosts: list of strings. A list of hosts for which the user can view
      events. An entry in the list can be:
      - An IPv4 address
      - An IPv6 address
      - A host name
      - A network address with it's subnet mask in the form of a string
        (e.g. '192.168.2.0/24')
    """
    manage_users = 'manage_users'
    restart_server = 'restart_server'
    get_configs = 'get_configs'
    set_configs = 'set_configs'
    hosts = 'hosts'

    def __init__(self, manage_users=False, restart_server=False,\
                 get_configs=True, set_configs=False, hosts=list()):
        try:
            self.manage_users = bool(manage_users)
            self.restart_server = bool(restart_server)
            self.get_configs = bool(get_configs)
            self.set_configs = bool(set_configs)
            self.hosts = list(hosts)
        except:
            logging.debug('Invalid UserPermissions parameters', exc_info=True)


    def serialize(self):
        serialized_object = dict()
        serialized_object[UserPermissions.manage_users] = self.manage_users
        serialized_object[UserPermissions.restart_server] = self.restart_server
        serialized_object[UserPermissions.get_configs] = self.get_configs
        serialized_object[UserPermissions.set_configs] = self.set_configs
        serialized_object[UserPermissions.hosts] = self.hosts
        return serialized_object


    @staticmethod
    def deserialize(db_obj):
        try:
            return UserPermissions(db_obj[UserPermissions.manage_users],\
                                   db_obj[UserPermissions.restart_server],\
                                   db_obj[UserPermissions.get_configs],\
                                   db_obj[UserPermissions.set_configs],\
                                   db_obj[UserPermissions.hosts])
        except:
            logging.debug('Invalid UserPermissions db object', exc_info=True)
            return None



class FailedUserValidation(Exception):

    def __init__(self, reason):
        self.err_msg = reason

    def __str__(self):
        return repr(self.err_msg)
