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
from ConfigParser import ConfigParser


class AgentConfig(ConfigParser):

    default_server_addr = '127.0.0.1'
    default_server_port = '20000'
    default_server_encrypt_port = '20001'
    default_encrypt_enabled = False

    file_name = 'umit_agent.conf'
    file_path = file_name

# General section options
    general_section = 'general_section'
    server_addr = 'server_address'
    encrypt_enabled = 'encryption_enabled'
    server_port = 'server_port'
    server_encrypt_port = 'server_encrypted_port'

# Monitoring Modules standard options
    module_enabled = 'enabled'
    module_path = 'path'


    def __init__(self, config_file_path = None):
        ConfigParser.__init__(self)

        self.config_file_path = config_file_path
        if config_file_path == None:
            self._set_default_settings()
        self.load_settings()


# File handling methods

    def load_default_settings(self):
        self._clear_settings()
        self._set_default_settings()


    def load_settings(self):
        # Try to create the configuration file if it does not exist.
        # Also load the default settings and save them in that file.
        if not os.path.isfile(self.config_file_path):
            config_file = open(self.config_file_path, 'w')
            self.load_default_settings()
            self.save_settings()
            self.read(self.config_file_path)
        else:
            config_file = open(self.config_file_path)
            self.readfp(config_file)


    def save_settings(self):
        config_file = open(self.config_file_path, 'w')
        self.write(config_file)


# General options methods

    def set_notifications_server_address(self, notifications_server_addr):
        self.notifications_server_addr = notifications_server_addr


    def get_notifications_server_address(self, notifications_server_addr):
        return self.notifications_server_addr


# Module options methods

    def module_is_installed(self, module_name):
        return self.has_section(module_name)


    def module_get_enable(self, module_name):
        if not self.module_is_installed(module_name):
            raise AgentConfig.ModuleNotInstalled(module_name)

        return self.getboolean(module_name, ENABLED)


    def module_set_enable(self, module_name, enable_value = True):
        if not self.module_is_installed(module_name):
            raise AgentConfig.ModuleNotInstalled(module_name)

        self.set(module_name, ENABLED, enable_value)


    def module_get_path(self, module_name):
        if not self.module_is_installed(module_name):
            raise AgentConfig.ModuleNotInstalled(module_name)

        return self.get(module_name, PATH)


    def module_set_path(self, module_name, path):
        if not self.module_is_installed(module_name):
            raise AgentConfig.ModuleNotInstalled(module_name)

        self.set(module_name, PATH, path)

    def module_set_option(self, module_name, option_name, option_value):
        if not self.module_is_installed(module_name):
            raise AgentConfig.ModuleNotInstalled(module_name)

        self.set(module_name, option_name, option_value)


    def module_get_option(self, module_name, option_name):
        if not self.module_is_installed(module_name):
            raise AgentConfig.ModuleNotInstalled(module_name)

        return self.get(module_name, option_name)


# Private methods

    def _clear_settings(self):
        sections = self.sections()
        for section in sections:
            self.remove_section(section)

    def _set_default_settings(self):
        # Fail-safe settings

        # General settings
        self.add_section(AgentConfig.general_section)
        self.set(AgentConfig.general_section, AgentConfig.encrypt_enabled,\
                AgentConfig.default_encrypt_enabled)
        self.set(AgentConfig.general_section, AgentConfig.server_addr,\
                AgentConfig.default_server_addr)
        self.set(AgentConfig.general_section, AgentConfig.server_port,\
                AgentConfig.default_server_port)
        self.set(AgentConfig.general_section, AgentConfig.server_encrypt_port,\
                AgentConfig.default_server_encrypt_port)

        # Module default settings
        self.add_section('DeviceSensor')
        self.set('DeviceSensor', AgentConfig.module_path,\
                os.path.join('umit', 'agent', 'monitoring_modules'))
        self.set('DeviceSensor', AgentConfig.module_enabled, True)

        self.add_section('TestModule')
        self.set('TestModule', AgentConfig.module_path,\
            os.path.join('umit', 'agent', 'monitoring_modules'))
        self.set('TestModule', AgentConfig.module_enabled, True)

        if os.name == 'posix':
            AgentConfig.file_path = os.path.join('/etc', AgentConfig.file_name)
        self.config_file_path = AgentConfig.file_path


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

