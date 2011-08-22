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
        self.set(InventoryConfig.general_section,
                ServerConfig.interface_port,
                str(ServerConfig.default_interface_port))
        self.set(InventoryConfig.general_section,
                 ServerConfig.force_interface_encrypt,
                 str(ServerConfig.default_force_interface_encrypt))

        self.add_section('Database')


    def _set_default_config_file(self):
        """Sets the default configuration file"""
        if os.name == 'nt':
            self.config_file_path = 'umit_server.conf'
        else:
            self.config_file_path = '/etc/umit_server.conf'


    def _get_default_log_path(self):
        if hasattr(self, 'default_log_path'):
            return self.default_log_path
        if os.name == 'posix':
            return os.path.abspath('/var/log/umit-notifications-server/')
        else:
            return os.path.abspath('logs\\umit-notifications-server\\')