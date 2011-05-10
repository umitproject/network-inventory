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

import os
import ConfigParser
from ConfigParser import RawConfigParser

# Definitions
POSIX = os.name == 'posix'
CONFIG_FILE_NAME = 'umit_agent' + ('.conf' if POSIX else '.ini')
if POSIX:
    CONFIG_FILE_PATH = os.path.join('etc', CONFIG_FILE_NAME)
else:
    CONFIG_FILE_PATH = CONFIG_FILE_NAME

GENERAL_SECTION = 'GeneralSettings'

# General settings standard options
SERVER = 'Server'

# Monitoring Modules standard options
ENABLED = 'Enabled'
PATH = 'Path'

# Default options values
DEFAULT_SERVER_ADDR = '127.0.0.1'
DEFAULT_MODULES = (ModuleConfiguration('Device_Sensor', enabled = True),\
                   ModuleConfiguration('Test_Module', enabled = False))


class AgentConfiguration(RawConfigParser):

    def __init__(self, config_file_path = None):
        if config_file_path == None:
            self.config_file_path = CONFIG_FILE_PATH


# File handling methods

    def load_default_settings(self):
        self._clear_settings()

        for module in DEFAULT_MODULES:
            RawConfigParser.add_section(self, module.name)
            RawConfigParser.set(self, module.name, ENABLED, module.enabled)
            RawConfigParser.set(self, module.name, PATH, module.path)

        RawConfigParser.add_section(self, GENERAL_SETTINGS)
        RawConfigParser.set(self, GENERAL_SECTION, SERVER, DEFAULT_SERVER_ADDR)


    def load_settings(self):
        # Try to create the configuration file if it does not exist.
        # Also load the default settings and save them in that file.
        if not os.path.is_file(self.config_file_path):
            config_file = open(self.config_file_path)
            self.load_default_settings()
            self.save_settings()
            RawConfigParser.readfp(self, config_file)
        else
            config_file = open(self.config_file_path)
            RawConfigParser.readfp(self, config_file)


    def save_settings(self, config_file_path = None):
        config_file = open(self.config_file_path)
        RawConfigParser.write(self, config_file)


# General options methods

    def set_notifications_server_address(self, notifications_server_addr):
        self.notifications_server_addr = notifications_server_addr


    def get_notifications_server_address(self, notifications_server_addr):
        return self.notifications_server_addr


# Module options methods

    def module_is_installed(self, module_name):
        return RawConfigParser.has_section(self, module_name)


    def module_get_enable(self, module_name):
        if not self.module_is_installed(module_name):
            error = AgentConfigurationError()
            error.set_module_not_installed(module_name)
            raise error

        return RawConfigParser.getboolean(self, module_name, ENABLED)


    def module_set_enable(self, module_name, enable_value = True):
        if not self.module_is_installed(module_name):
            error = AgentConfigurationError()
            error.set_module_not_installed(module_name)
            raise error

        RawConfigParser.set(self, module_name, ENABLED, enable_value)


    def module_get_path(self, module_name):
        if not self.module_is_installed(module_name):
            error = AgentConfigurationError()
            error.set_module_not_installed(module_name)
            raise error

        return RawConfigParser.get(self, module_name, PATH)


    def module_set_path(self, module_name, path):
        if not self.module_is_installed(module_name):
            error = AgentConfigurationError()
            error.set_module_not_installed(module_name)
            raise error

        RawConfigParser.set(self, module_name, PATH, path)


# Private methods

    def _clear_settings(self):
        sections = RawConfigParser.sections(self)
        for section in sections:
            RawConfigParser.remove_section(self, section)



class AgentConfigurationError(Exception):

    def __init__(self, value = None):
        self.error_message = value


    def set_module_not_installed(self, module_name):
        self.error_message = 'Module ' + str(module_name) + ' not installed'


    def __str__(self):
        return repr(self.error_message)


class ModuleConfiguration:

    def __init__(self, name, path = '.', enabled = False):
        self.name = name
        self.path = path
        self.enabled = enabled
