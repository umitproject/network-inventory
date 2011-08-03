#!/usr/bin/env python
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

from umit.inventory.gui.ServerCommunicator import SearchRequest
from umit.inventory.gui.ServerCommunicator import SearchNextRequest
from umit.inventory.gui.ServerCommunicator import SearchStopRequest


class NIShell:
    
    def __init__(self, core):
        self.core = core
        self.communicator = self.core.server_communicator
        self.ui_manager = None
        self.modules = dict()
        self.host_names = []
        self.host_ipv4_addresses = {}
        self.host_ipv6_addresses = {}


    def set_user_data(self, username, password):
        self.username = username
        self.password = password


    def set_hostnames(self, hostnames):
        self.host_names = hostnames


    def set_ipv4_addresess(self, ipv4_addresses):
        i = 0
        for i in range(len(self.host_names)):
            self.host_ipv4_addresses[self.host_names[i]] = ipv4_addresses[i]


    def set_ipv6_addresess(self, ipv6_addresses):
        i = 0
        for i in range(len(self.host_names)):
            self.host_ipv6_addresses[self.host_names[i]] = ipv6_addresses[i]


    def initialize_modules(self):
        self.modules = self.core.modules


    def request_config_pages(self, config_window_manager):
        # Called by the ConfigurationWindowManager when pages should be added
        # to the config window
        for module in self.modules.values():
            module.add_configs_ui(config_window_manager)


    # General functionality

    def register_async_handler(self, async_type, async_handler):
        """
        Used to register async response types to a given handler.
        The handler must be a function taking only one argument: the body of
        the response.
        """
        self.core.register_async_handler(async_type, async_handler)


    def send_request(self, request):
        print 'sending request ...'
        self.communicator.send_request(request)


    def get_username(self):
        return self.username


    def get_password(self):
        return self.password


    def get_host_names(self):
        return self.host_names


    def get_host_ipv4_address(self, hostname):
        try:
            return self.host_ipv4_addresses[hostname]
        except:
            return None


    def get_host_ipv6_address(self, hostname):
        try:
            return self.host_ipv6_addresses[hostname]
        except:
            return None


    # Searching notifications functions

    def search_notifications(self, spec, sort, fields, callback):
        """
        callback: A function with the following signature
        callback(notifications_list=None, search_id=None, count=0, failed=False)
        """
        search_request = SearchRequest(self.username, self.password, spec,\
                                       fields, sort, callback)
        self.communicator.send_request(search_request)


    def get_next_search_results(self, search_id, start_index, callback):
        search_request = SearchNextRequest(self.username, self.password,\
                                           search_id, start_index, callback)
        self.communicator.send_request(search_request)


    def stop_search(self, search_id):
        search_request = SearchStopRequest(self.username, self.password,
                                           search_id)
        self.communicator.send_request(search_request)

