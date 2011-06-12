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
from umit.inventory.common import InventoryConfig


class ServerConfig(InventoryConfig):

    file_path = os.path.join('umit', 'inventory', 'server', 'umit_server.conf')

    # Default values
    default_interface_port = '30000'

    # General section options
    general_section = 'GeneralSection'
    interface_port = 'interface_port'


    def get_core_modules(self):
        return ['Database']


    def _set_default_settings(self):
        """Load default fail-safe settings"""

        # General settings
        self.add_section(InventoryConfig.general_section)
        self.set(InventoryConfig.general_section,\
                ServerConfig.interface_port,\
                ServerConfig.default_interface_port)

        # Module default settings
        self.add_section('AgentListener')
        self.set('AgentListener', InventoryConfig.module_path,\
                os.path.join('umit', 'inventory', 'server', 'modules'))
        self.set('AgentListener', InventoryConfig.module_enabled, True)

        self.add_section('SNMPListener')
        self.set('SNMPListener', InventoryConfig.module_path,\
                os.path.join('umit', 'inventory', 'server', 'modules'))
        self.set('SNMPListener', InventoryConfig.module_enabled, False)

        self.add_section('Database')
        self.set('Database', InventoryConfig.module_path,\
                os.path.join('umit', 'inventory', 'server'))
        self.set('Database', InventoryConfig.module_enabled, True)


    def _set_default_config_file(self):
        """Sets the default configuration file"""
        self.config_file_path = ServerConfig.file_path


