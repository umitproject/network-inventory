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


class Module:
    """ Abstract GUI Module class """


    def __init__(self, ui_manager, shell):
        self.ui_manager = ui_manager
        self.shell = shell


    def set_configs(self, configs):
        """
        Called when the GUI receives the configurations from the server.
        Should be implemented.
        """
        pass


    def add_configs_ui(self, config_window_manager):
        """
        Called when the module should add pages to the configuration
        window.
        config_window_manager: The ConfigurationWindowManager object.
        Should be implemented.
        """
        pass


    def add_notebook_page(self, notebook):
        """
        Called when the module should add pages to the general GUI notebook.
        Should be implemented.
        """
        pass


    def get_host_views(self):
        """
        Returns a list of host views (which implement AbstractHostView) to
        be added to the 'Network Hosts' tab.
        Should be implemented.
        """
        return []


    def get_event_widget(self, notification):
        """
        Called when the module should return a widget that will show details
        from the notification. If the notification isn't meant for this module
        then None should be returned.
        Should be implemented.
        """
        return None


    def get_event_window_name(self):
        """
        Returns the name that will be shown in the event window when showing
        information from this module.
        Should be implemented.
        """
        return None