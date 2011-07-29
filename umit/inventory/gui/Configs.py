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


class NIConfig(InventoryConfig):

    file_path = os.path.join('umit', 'inventory', 'gui', 'umit_ni_gui.conf')

    # General section options
    ni_server_host = 'notifications_server_host'
    ni_server_port = 'notifications_server_port'
    ni_server_username = 'notifications_server_username'
    ni_server_enable_ssl = 'enable_encryption_with_notifications_server'


    def _set_default_settings(self):
        """Load default fail-safe settings"""
        InventoryConfig._set_default_settings(self)
    
        # Module default settings
        self.add_section('SNMPModule')
        self.set('SNMPModule', InventoryConfig.module_path,\
                os.path.join('umit', 'inventory', 'gui', 'modules'))
        self.set('SNMPModule', InventoryConfig.module_enabled, True)
        self.set('SNMPModule', InventoryConfig.is_module, True)

        self.add_section('UmitAgentModule')
        self.set('UmitAgentModule', InventoryConfig.module_path,\
                os.path.join('umit', 'inventory', 'gui', 'modules'))
        self.set('UmitAgentModule', InventoryConfig.module_enabled, True)
        self.set('UmitAgentModule', InventoryConfig.is_module, True)


    def _set_default_config_file(self):
        """Sets the default configuration file"""
        self.config_file_path = NIConfig.file_path


    def _get_default_log_path(self):
        if os.name == 'posix':
            return os.path.abspath('/var/log/umit-ni-gui/')
        else:
            return os.path.abspath('logs\\umit-ni-gui\\')