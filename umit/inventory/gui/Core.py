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

import gtk
from gobject import GObject
import gobject
import traceback

gtk.gdk.threads_init()


class NICore(GObject):
    """ Network Inventory GUI Core """

    def __init__(self, configurations):
        GObject.__init__(self)
        self.conf = configurations
        self.shell = NIShell(self)
        self.server_communicator = NIServerCommunicator(self, configurations)
        self.ui_manager = NIUIManager(self, configurations)

        self._load_modules()
        self._init_handlers()

        self.logged_in = False
        self.network_message_recv = False
        


    def _load_modules(self):
        pass


    def _init_handlers(self):
        self.ui_manager.connect('shutdown', self.on_shutdown)
        self.ui_manager.connect('login', self.on_login)
        self.ui_manager.connect('subscribe', self.on_ui_subscribe_request)
        self.ui_manager.connect('unsubscribe', self.on_ui_unsubscribe_request)


    def run(self):
        self.server_communicator.start()
        self.ui_manager.set_login_state()
        gtk.main()


    def handle_async_message(self, msg):
        try:
            response_type = msg['response_type']
            body = msg['body']
        except:
            traceback.print_exc()
            return

        if response_type == 'SUBSCRIBE_RESPONSE':
            self.ui_manager.add_events_view_notification(body)


    # Methods called by the ServerCommunicator

    def set_login_failed(self, msg):
        gobject.idle_add(self.ui_manager.show_auth_state_error, msg,\
                         'Authentication Failed')


    def set_login_success(self, permissions, protocols):
        self.logged_in = True
        self.permissions = permissions
        gobject.idle_add(self.ui_manager.set_protocols, protocols)
        gobject.idle_add(self.ui_manager.set_run_state)
        gobject.idle_add(self.server_communicator.send_request,\
            SubscribeRequest(self.username, self.password))

    def set_connection_failed(self):
        msg = 'Fatal Error: Connection closed by the Notifications Server'
        second_title = 'Shutting Down'
        gobject.idle_add(self.ui_manager.show_run_state_error, msg, second_title)
        gobject.idle_add(gtk.main_quit)


    def set_async_message_received(self, msg):
        gobject.idle_add(self.handle_async_message, msg)


    # Handlers

    def on_shutdown(self, emitting_obj):
        """ Called when we should shutdown """
        self.server_communicator.shutdown()
        gtk.mainquit()


    def on_login(self, emitting_obj, uname, password, host, port, ssl_enabled):
        self.username = uname
        self.password = password
        self.server_communicator.connect(uname, password, host,\
                                         port, ssl_enabled)


    def on_ui_subscribe_request(self, emitting_obj, protocol, hosts, types):
        req = SubscribeRequest(self.username, self.password, types,\
                               hosts, protocol)
        self.server_communicator.send_request(req)


    def on_ui_unsubscribe_request(self, emitting_obj):
        req = UnsubscribeRequest(self.username, self.password)
        self.server_communicator.send_request(req)
