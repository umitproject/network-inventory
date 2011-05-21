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
import time
import os
import socket
from ConfigParser import ConfigParser


class NotificationTypes:

    info = "INFO"
    warning = "WARNING"
    recovery = "RECOVERY"
    critical = "CRITICAL"
    emergency = "EMERGENCY"



class NotificationFields:

    source_host = 'SourceHost'
    timestamp = 'Timestamp'
    message = 'Message'
    message_type = 'Type'
    monitoring_module = 'MonitoringModule'
    module_fields = 'ModuleFields'



class NotificationParser:

    @staticmethod
    def parse(message, msg_type, fields):
        """Parses the message into the internal format (JSON)"""
        message_obj = dict()
        message_obj[NotificationFields.message] = message
        message_obj[NotificationFields.message_type] = msg_type
        message_obj[NotificationFields.timestamp] = time.time()
        # TODO : get the IP address of the Host
        message_obj[NotificationFields.source_host] = socket.gethostname()
        message_obj[NotificationFields.module_fields] = dict()
        for i in fields.keys():
            message_obj[NotificationFields.module_fields][i] = fields[i]

        return json.dumps(message_obj)



class InventoryConfig(ConfigParser):

    # General section options
    general_section = 'GeneralSection'

    # Modules standard options
    module_enabled = 'enabled'
    module_path = 'path'


    def __init__(self, config_file_path=None):
        ConfigParser.__init__(self)

        self.config_file_path = config_file_path
        if config_file_path == None:
            self._set_default_config_file()

        if self.config_file_path == None:
            self.load_default_settings()
        else:
            self.load_settings()


    # File handling methods

    def load_default_settings(self):
        self._clear_settings()
        self._set_default_settings()


    def load_settings(self):
        """
        Loads the settings from the file located at self.config_file_path.
        If that file doesn't exist it will try to create it. If it can't create
        it, then it will raise an InventoryConfig.ConfigFile exception.
        The newly created file will also be filled with the default settings.
        """
        if not os.path.isfile(self.config_file_path):
            try:
                config_file = open(self.config_file_path, 'w')
            except:
                raise InventoryConfig.ConfigFile(self.config_file_path)

            self.load_default_settings()
            self.save_settings()
            self.read(self.config_file_path)
        else:
            config_file = open(self.config_file_path)
            self.readfp(config_file)


    def save_settings(self):
        """Saves the settings in the file located at self.config_file_path"""
        config_file = open(self.config_file_path, 'w')
        self.write(config_file)


    # General options methods

    def set_general_option(self, option_name, option_value):
        """Set an option which will be saved in the GeneralSettings section"""
        self.set(InventoryConfig.general_section, option_name, option_value)


    def get_general_option(self, option_name):
        """Get an option which is saved in the GeneralSettings section"""
        return self.get(InventoryConfig.general_section, option_name)


    # Module options methods

    def get_modules_list(self):
        """Returns a list with the Module names located in the config file"""
        modules_list = self.sections()
        modules_list.remove(InventoryConfig.general_section)
        return modules_list


    def module_is_installed(self, module_name):
        """Returns True if module_name is installed. False otherwise"""
        return self.has_section(module_name)


    def module_get_enable(self, module_name):
        """
        Returns True if the module with the name module_name is enabled.
        False otherwise.
        Raises InventoryConfig.ModuleNotInstalled if module_name is not installed.
        """
        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        return self.getboolean(module_name, InventoryConfig.module_enabled)


    def module_set_enable(self, module_name, enable_value=True):
        """
        Sets the module with the name module_name to be enabled if enable_value
        is True.
        Raises InventoryConfig.ModuleNotInstalled if module_name is not installed
        """
        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        self.set(module_name, InventoryConfig.module_enabled, enable_value)


    def module_set_option(self, module_name, option_name, option_value):
        """Sets an option for a given module"""
        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        self.set(module_name, option_name, option_value)


    def module_get_option(self, module_name, option_name):
        """Used to get an option for a given module"""
        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        return self.get(module_name, option_name)


    def module_set_options(self, module_name, option_dict, overwrite=True):
        """
        Used to set the options in option_dict, which is a dictionary with
        entries of the type [option_name, option_value]. If overwrite is set
        to False, any existing values will not be overwritten.
        """
        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        for option_name in option_dict.keys():
            if not overwrite and self.has_option(module_name, option_name):
                continue
            self.set(module_name, option_name, option_dict[option_name])


    # Private methods

    def _clear_settings(self):
        """Clears the current settings"""
        sections = self.sections()
        for section in sections:
            self.remove_section(section)

    def _set_default_settings(self):
        """Load default fail-save settings"""
        pass
        
    def _set_default_config_file(self):
        """Sets the default configuration file"""
        pass


    # Exceptions

    class ModuleNotInstalled(Exception):

        def __init__(self, module_name):
            self.err_message = 'Module ' + str(module_name) + ' not installed'

        def __str__(self):
            return repr(self.err_message)


    class GeneralError(Exception):

        def __init__(self, value):
            self.err_message = str(value)

        def __str__(self):
            return repr(self.err_message)


    class ConfigFile(Exception):

        def __init__(self, value):
            self.err_message = 'Can\'t open ' + str(value)

        def __str__(self):
            return repr(self.err_message)


