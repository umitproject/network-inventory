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

from umit.inventory.gui.Shell import NIShell
from umit.inventory.gui.ServerCommunicator import NIServerCommunicator
from umit.inventory.gui.UIManager import NIUIManager
from umit.inventory.gui.ServerCommunicator import SubscribeRequest
from umit.inventory.gui.ServerCommunicator import UnsubscribeRequest
from umit.inventory.gui.ServerCommunicator import GetHostsRequest
from umit.inventory.gui.ServerCommunicator import GetConfigsRequest
from umit.inventory.gui.Configs import NIConfig
import umit.inventory.common

import gtk
from gobject import GObject
import gobject
import traceback

gtk.gdk.threads_init()


class NICore(GObject):
    """ Network Inventory GUI Core """

    def __init__(self, configurations, data_dir):
        GObject.__init__(self)
        self.data_dir = data_dir
        
        # Mapping async types to their handlers
        self.registered_async_handlers = dict()

        self.conf = configurations
        self.server_communicator = NIServerCommunicator(self, configurations)
        self.shell = NIShell(self)
        self.ui_manager = NIUIManager(self, configurations)
        self.shell.ui_manager = self.ui_manager

        self.modules = dict()
        self._load_modules()
        self._init_handlers()
        self.shell.initialize_modules()

        self.logged_in = False
        self.network_message_recv = False


    def _load_modules(self):
        modules_objects =\
            umit.inventory.common.load_modules_from_target('gui',
                self.ui_manager, self.shell)
        for module_object in modules_objects:
            self.modules[module_object.__class__.__name__] = module_object

        for module in self.modules.values():
            # Add the module host views
            host_views = module.get_host_views()
            for host_view in host_views:
                self.ui_manager.hosts_view_manager.add_host_detail_view(host_view)

            # Add the notebook pages
            module.add_notebook_page(self.ui_manager.ni_notebook)


    def _init_handlers(self):
        self.ui_manager.connect('shutdown', self.on_shutdown)
        self.ui_manager.connect('login', self.on_login)
        self.ui_manager.connect('subscribe', self.on_ui_subscribe_request)
        self.ui_manager.connect('unsubscribe', self.on_ui_unsubscribe_request)


    def run(self):
        self.server_communicator.start()
        self.ui_manager.set_login_state()
        gtk.main()


    def register_async_handler(self, async_type, async_handler):
        self.registered_async_handlers[async_type] = async_handler


    def handle_async_message(self, msg):
        try:
            response_type = msg['response_type']
            body = msg['body']
        except:
            traceback.print_exc()
            return

        if response_type == 'SUBSCRIBE_RESPONSE':
            self.ui_manager.add_events_view_notification(body)
            return
        
        try:
            self.registered_async_handlers[response_type](body)
        except:
            traceback.print_exc()


    def set_configs(self, configs=dict(), failed=False):
        if failed:
            return

        for module in self.modules.values():
            module.set_configs(configs)

        # Enable configurations on the UI side
        self.ui_manager.enable_configurations()


    # Methods called by the ServerCommunicator

    def set_login_failed(self, msg):
        gobject.idle_add(self.ui_manager.show_auth_state_error, msg,\
                         'Authentication Failed')


    def set_login_success(self, permissions, protocols):
        self.logged_in = True
        self.permissions = permissions
        gobject.idle_add(self.ui_manager.set_protocols, protocols)
        gobject.idle_add(self.ui_manager.set_run_state)
        gobject.idle_add(self.server_communicator.send_request,
            SubscribeRequest(self.username, self.password))
        gobject.idle_add(self.server_communicator.send_request,
            GetHostsRequest(self.username, self.password, self))
        gobject.idle_add(self.server_communicator.send_request,
            GetConfigsRequest(self.username, self.password, self))
        gobject.idle_add(self.shell.set_user_data, self.username, self.password)
        
        self.conf.set_general_option(NIConfig.ni_server_username, self.username)
        self.conf.set_general_option(NIConfig.ni_server_host, self.host)
        self.conf.set_general_option(NIConfig.ni_server_port, self.port)
        self.conf.set_general_option(NIConfig.ni_server_enable_ssl,
                                     self.ssl_enabled)
        self.conf.save_settings()


    def set_connection_failed(self):
        msg = 'Fatal Error: Connection closed by the Notifications Server'
        second_title = 'Shutting Down'
        gobject.idle_add(self.ui_manager.show_run_state_error, msg,
                         second_title, True)


    def set_async_message_received(self, msg):
        gobject.idle_add(self.handle_async_message, msg)


    def set_host_info(self, hostnames, ipv4_addresses, ipv6_addresses):
        self.hostnames = hostnames
        self.ipv4_addresses = ipv4_addresses
        self.ipv6_addresses = ipv6_addresses

        # TODO - decide what to do with IPv6 here.
        gobject.idle_add(self.ui_manager.set_hostnames, hostnames)
        gobject.idle_add(self.ui_manager.set_ips, ipv4_addresses)
        gobject.idle_add(self.shell.set_hostnames, hostnames)
        gobject.idle_add(self.shell.set_ipv4_addresess, ipv4_addresses)
        gobject.idle_add(self.shell.set_ipv6_addresess, ipv6_addresses)


    # Handlers

    def on_shutdown(self, emitting_obj):
        """ Called when we should shutdown """
        self.server_communicator.shutdown()
        gtk.mainquit()


    def on_login(self, emitting_obj, uname, password, host, port, ssl_enabled):
        self.username = uname
        self.password = password
        self.host = host
        self.port = port
        self.ssl_enabled = ssl_enabled
        self.server_communicator.connect(uname, password, host,\
                                         port, ssl_enabled)


    def on_ui_subscribe_request(self, emitting_obj, protocol, hosts, types):
        req = SubscribeRequest(self.username, self.password, types,\
                               hosts, protocol)
        self.server_communicator.send_request(req)


    def on_ui_unsubscribe_request(self, emitting_obj):
        req = UnsubscribeRequest(self.username, self.password)
        self.server_communicator.send_request(req)
