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


class ServerConfig(InventoryConfig):

    file_path = os.path.join('umit', 'inventory', 'server', 'umit_server.conf')

    # Default values
    default_interface_port = '30000'
    default_force_interface_encrypt = False

    # General section options
    interface_port = 'interface_port'
    force_interface_encrypt = 'force_interface_encrypt'


    def _set_default_settings(self):
        """Load default fail-safe settings"""
        InventoryConfig._set_default_settings(self)

        # General settings
        self.set(InventoryConfig.general_section,\
                ServerConfig.interface_port,\
                str(ServerConfig.default_interface_port))
        self.set(InventoryConfig.general_section,\
                 ServerConfig.force_interface_encrypt,\
                 str(ServerConfig.default_force_interface_encrypt))
    
        # Module default settings
        # !! TODO - refactor this is another place. This should be added trough
        # !! a ServerCore add_module() method.
        self.add_section('AgentListener')
        self.set('AgentListener', InventoryConfig.module_path,
                os.path.join('umit', 'inventory', 'server', 'modules'))
        self.set('AgentListener', InventoryConfig.module_enabled, True)
        self.set('AgentListener', InventoryConfig.is_module, True)

        self.add_section('SNMPListener')
        self.set('SNMPListener', InventoryConfig.module_path,
                os.path.join('umit', 'inventory', 'server', 'modules'))
        self.set('SNMPListener', InventoryConfig.module_enabled, True)
        self.set('SNMPListener', InventoryConfig.is_module, True)

        self.add_section('EmailSender')
        self.set('EmailSender', InventoryConfig.module_path,
                os.path.join('umit', 'inventory', 'server', 'modules'))
        self.set('EmailSender', InventoryConfig.module_enabled, False)
        self.set('EmailSender', InventoryConfig.is_module, True)

        self.add_section('DeviceSensor')
        self.set('DeviceSensor', InventoryConfig.module_path,
                os.path.join('umit', 'inventory', 'server', 'modules'))
        self.set('DeviceSensor', InventoryConfig.module_enabled, True)
        self.set('DeviceSensor', InventoryConfig.is_module, True)

        self.add_section('NetworkAdministratorSender')
        self.set('NetworkAdministratorSender', InventoryConfig.module_path,
                os.path.join('umit', 'inventory', 'server', 'modules'))
        self.set('NetworkAdministratorSender', InventoryConfig.module_enabled, False)
        self.set('NetworkAdministratorSender', InventoryConfig.is_module, True)

        self.add_section('Database')


    def _set_default_config_file(self):
        """Sets the default configuration file"""
        self.config_file_path = ServerConfig.file_path


    def _get_default_log_path(self):
        if os.name == 'posix':
            return os.path.abspath('/var/log/umit-notifications-server/')
        else:
            return os.path.abspath('logs\\umit-notifications-server\\')