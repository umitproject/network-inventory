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
from umit.inventory.Configuration import InventoryConfig


class AgentConfig(InventoryConfig):

    # Default values
    default_server_addr = '127.0.0.1'
    default_server_port = '20000'
    default_ssl_enabled = False
    default_polling_time = 2.0
    default_max_notification_queue_size = 1000
    default_auth_enabled = False
    default_username = 'guest'
    default_password = 'guest'

    file_path = os.path.join('umit', 'inventory', 'agent', 'umit_agent.conf')

    # General section options
    server_addr = 'server_address'
    ssl_enabled = 'ssl_enabled'
    server_port = 'server_port'
    polling_time = 'polling_time_interval'
    max_notification_queue_size = 'max_notification_queue_size'
    auth_enabled = 'authentication_enabled'
    username = 'username'
    password = 'password'


    def _set_default_settings(self):
        """Load default fail-save settings"""
        InventoryConfig._set_default_settings(self)
        
        # General settings
        self.set(InventoryConfig.general_section, AgentConfig.ssl_enabled,\
                 str(AgentConfig.default_ssl_enabled))
        self.set(InventoryConfig.general_section, AgentConfig.server_addr,\
                 str(AgentConfig.default_server_addr))
        self.set(InventoryConfig.general_section, AgentConfig.server_port,\
                 str(AgentConfig.default_server_port))
        self.set(InventoryConfig.general_section,\
                 AgentConfig.max_notification_queue_size,\
                 str(AgentConfig.default_max_notification_queue_size))
        self.set(InventoryConfig.general_section, AgentConfig.polling_time,\
                 str(AgentConfig.default_polling_time))
        self.set(InventoryConfig.general_section, AgentConfig.auth_enabled,\
                 str(AgentConfig.default_auth_enabled))
        self.set(InventoryConfig.general_section, AgentConfig.username,\
                 str(AgentConfig.default_username))
        self.set(InventoryConfig.general_section, AgentConfig.password,\
                 str(AgentConfig.default_password))

        # Module default settings
        self.add_section('DeviceSensor')
        self.set('DeviceSensor', AgentConfig.module_path,\
                os.path.join('umit', 'inventory', 'agent', 'modules'))
        self.set('DeviceSensor', AgentConfig.module_enabled, True)
        self.set('DeviceSensor', AgentConfig.is_module, True)

        self.add_section('TestModule')
        self.set('TestModule', AgentConfig.module_path,\
            os.path.join('umit', 'inventory', 'agent', 'modules'))
        self.set('TestModule', AgentConfig.module_enabled, False)
        self.set('DeviceSensor', AgentConfig.is_module, True)


    def _set_default_config_file(self):
        """Sets the default configuration file"""
        self.config_file_path = AgentConfig.file_path


    def _get_default_log_path(self):
        if os.name == 'posix':
            return os.path.abspath('/var/log/agent/')
        else:
            return os.path.abspath('logs\\umit-agent\\')