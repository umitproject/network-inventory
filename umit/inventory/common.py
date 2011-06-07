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
import traceback


class NotificationTypes:

    info = "INFO"
    warning = "WARNING"
    recovery = "RECOVERY"
    critical = "CRITICAL"
    emergency = "EMERGENCY"



class AgentFields:

    source_host = 'source_host'
    timestamp = 'timestamp'
    message = 'message'
    message_type = 'type'
    monitoring_module = 'monitoring_module'
    module_fields = 'module_fields'



class AgentNotificationParser:
    """ The Notification Parser for the Umit Agent """

    @staticmethod
    def parse(message, msg_type, fields, module):
        """Parses the message into the internal format (JSON)"""
        message_obj = dict()
        message_obj[AgentFields.message] = message
        message_obj[AgentFields.message_type] = msg_type
        message_obj[AgentFields.timestamp] = time.time()
        message_obj[AgentFields.monitoring_module] = module
        # TODO : get the IP address of the Host
        message_obj[AgentFields.source_host] = socket.gethostname()
        message_obj[AgentFields.module_fields] = dict()
        for i in fields.keys():
            message_obj[AgentFields.module_fields][i] = fields[i]

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
        if InventoryConfig.general_section in modules_list:
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



def load_module(module_name, module_path, *module_args):
    """Loads a module with the given name from the given path."""

    path_tokens = module_path.split('/') # TODO - for Windows
    modname = ''
    for path_token in path_tokens:
        modname += path_token + '.'
    modname += module_name

    # Try importing from the path. If we fail at this step then the path is
    # invalid or we don't have permissions.
    try:
        module_mod = __import__(modname, globals(),\
                locals(), [module_name], -1)
    except Exception, e:
        traceback.print_exc()
        raise CorruptInventoryModule(module_name, module_path,\
                CorruptInventoryModule.corrupt_path)

    # Try to get a reference to the class of this Module.
    try:
        mod_class = module_mod.__dict__[module_name]
    except:
        raise CorruptInventoryModule(module_name, module_path,\
                CorruptInventoryModule.corrupt_file)

    # Return the initialized object
    return mod_class(*module_args)



class CorruptInventoryModule(Exception):
    """
    It is inherited by specific Exception classes for the Agent and Server
    modules.

    An exception generated when the module couldn't be loaded. Generic cases:
        corrupt_path: The file called [module_name].py couldn't be located at
                      the specified path.
        corrupt_file: The file [module_name].py was found at the specified
                      path, but it didn't contained a class called
                      [module_name].
        get_name:     The module doesn't implement the mandatory get_name()
                      method or it's result is incorrect.
    """

    corrupt_path = 0
    corrupt_file = 1

    def __init__(self, module_name, module_path, err_type=0):
        self.err_message = 'Module ' + str(module_name) + ':'
        if err_type == CorruptInventoryModule.corrupt_path:
            self.err_description = module_path + '/' + module_name + '.py ' +\
                    ' not found, missing permissions or invalid syntax'
        elif err_type == CorruptInventoryModule.corrupt_file:
            self.err_description = module_path + '/' + module_name + '.py ' +\
                    'doesn\'t contain a class called ' + module_name
        else:
            self.err_description = 'Undefined error'


    def __str__(self):
        return repr(self.err_message + self.err_description)


