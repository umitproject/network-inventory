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


    def set_user_data(self, username, password):
        self.username = username
        self.password = password


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
        self.communicator.sent_request(search_request)

