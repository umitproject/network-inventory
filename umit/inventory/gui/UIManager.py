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

import os
import gtk
import gobject

from umit.inventory.gui.Configs import NIConfig
from umit.inventory.gui.EventsViewManager import EventsViewManager
from umit.inventory.gui.HostsViewManager import HostsViewManager
from umit.inventory.gui.EventWindowManager import EventWindowManager
from umit.inventory.gui.ReportsHostsView import ReportsHostsView


# TODO needs refactoring
glade_files_path = os.path.join('umit', 'inventory', 'gui', 'glade_files')
ni_main_window_file = os.path.join(glade_files_path, 'ni_main.glade')
ni_auth_window_file = os.path.join(glade_files_path, 'ni_auth_window.glade')
ni_events_view_file = os.path.join(glade_files_path, 'ni_events_view.glade')
ni_event_window_file = os.path.join(glade_files_path, 'ni_event_window.glade')
ni_search_window_file = os.path.join(glade_files_path, 'ni_search_window.glade')
ni_time_date_picker_file = os.path.join(glade_files_path,\
                                        'ni_time_date_picker.glade')
ni_search_results_window = os.path.join(glade_files_path,\
                                        'ni_search_results_window.glade')
ni_hosts_view_file = os.path.join(glade_files_path, 'ni_hosts_view.glade')
ni_reports_hosts_view = os.path.join(glade_files_path,\
                                     'ni_reports_hosts_view.glade')


class NIUIManager(gobject.GObject):
    __gsignals__ = {
        # Emitted when there is a GUI event which should shutdown
        # the Network Inventory GUI
        "shutdown": (gobject.SIGNAL_RUN_FIRST,
                     gobject.TYPE_NONE,
                     ()),
        # Emitted when the user enters valid arguments in the login window
        # Parameters: username, password, host, port, ssl_enabled
        "login": (gobject.SIGNAL_RUN_FIRST,
                  gobject.TYPE_NONE,
                  (str, str, str, int, bool)),
        # Emitted when the user wants to subscribe with the given options.
        # Parameters: protocol, hosts (list), types (list)
        "subscribe": (gobject.SIGNAL_RUN_FIRST,
                      gobject.TYPE_NONE,
                      (str, gobject.TYPE_PYOBJECT, gobject.TYPE_PYOBJECT)),
        # Emitted when the user wants to unsubscribe.
        "unsubscribe": (gobject.SIGNAL_RUN_FIRST,
                        gobject.TYPE_NONE,
                        ()),
        # Emitted when the we are asking for a module specific widget to
        # display event details
        # Parameters: notification object, gtk.Container to add the widget,
        #             gtk.Label to put the module name
        "show-event-details": (gobject.SIGNAL_RUN_FIRST,
                               gobject.TYPE_NONE,
                               (gobject.TYPE_PYOBJECT, gobject.TYPE_OBJECT,\
                                gobject.TYPE_OBJECT)),
        }

    glade_files = {\
        'main' : ni_main_window_file,\
        'auth' : ni_auth_window_file,\
        'events_view' : ni_events_view_file,\
        'event_window' : ni_event_window_file,\
        'search_window' : ni_search_window_file,\
        'time_picker' : ni_time_date_picker_file,\
        'search_results' : ni_search_results_window,\
        'hosts_view' : ni_hosts_view_file,\
        'reports_hosts' : ni_reports_hosts_view\
    }

    def __init__(self, core, conf):
        gobject.GObject.__init__(self)
        self.core = core
        self.conf = conf

        self.logged_in = False
        
        # Basic widgets initialization
        self.main_window = None
        self.auth_window = None
        self.events_view = None
        self.event_window = None
        self.init_main_window()
        self.init_auth_window()
        self.init_events_view()
        self.init_hosts_view()
        self.init_event_window()


    def init_main_window(self):
        builder = gtk.Builder()
        builder.add_from_file(ni_main_window_file)
        self.main_window = builder.get_object('ni_main_window')

        self.ni_notebook = builder.get_object('ni_notebook')
        self.ni_toolbar = builder.get_object('ni_toolbar')
        self.ni_statusbar = builder.get_object('ni_statusbar')
        self.ni_menubar = builder.get_object('ni_menubar')

        self.ni_notebook.remove_page(2)
        self.ni_notebook.remove_page(1)
        self.ni_notebook.remove_page(0)

        self.main_window.connect('destroy', self.on_main_window_destroyed)


    def init_auth_window(self):
        builder = gtk.Builder()
        builder.add_from_file(ni_auth_window_file)
        self.auth_window = builder.get_object('auth_window')

        # Get the widgets
        self.aw_close_button = builder.get_object('close_button')
        self.aw_login_button = builder.get_object('login_button')
        self.username_te = builder.get_object('username_te')
        self.password_te = builder.get_object('password_te')
        self.host_te = builder.get_object('host_te')
        self.port_te = builder.get_object('port_te')
        self.enable_encryption_cb = builder.get_object('enable_encryption_cb')

        # Connect the handlers
        self.aw_close_button.connect('clicked',\
                                     self.on_auth_window_close_button_clicked)
        self.aw_login_button.connect('clicked',\
                                     self.on_auth_window_login_button_clicked)
        self.auth_window.connect('destroy', self.on_auth_window_destroyed)

        # Initialize the text entries if configured
        self.init_auth_window_text_entries()


    def show_auth_state_error(self, error_msg, error_second_title):
        error_dialog = gtk.MessageDialog(parent=self.auth_window,\
                                         type=gtk.MESSAGE_ERROR,\
                                         flags=gtk.DIALOG_MODAL,\
                                         buttons=gtk.BUTTONS_OK)
        error_dialog.set_property('text', error_second_title)
        error_dialog.set_title('Authentication Error')
        error_dialog.set_property('secondary-text', error_msg)
        error_dialog.connect('response', self.on_dialog_response, False)
        error_dialog.show()


    def show_run_state_error(self, error_msg, error_second_title, fatal=False):
        error_dialog = gtk.MessageDialog(parent=self.main_window,\
                                         type=gtk.MESSAGE_ERROR,\
                                         buttons=gtk.BUTTONS_OK)
        error_dialog.set_property('text', error_second_title)
        error_dialog.set_title('Runtime Error')
        error_dialog.set_property('secondary-text', error_msg)
        error_dialog.connect('response', self.on_dialog_response, fatal)
        error_dialog.show()


    def on_dialog_response(self, dialog, response_id, fatal):
        dialog.destroy()
        if fatal:
            gtk.main_quit()


    def init_auth_window_text_entries(self):
        username = self.conf.get_general_option(NIConfig.ni_server_username)
        if username is not None:
            self.username_te.set_text(username)

        host = self.conf.get_general_option(NIConfig.ni_server_host)
        if host is not None:
            self.host_te.set_text(host)

        port = self.conf.get_general_option(NIConfig.ni_server_port)
        if port is not None:
            self.port_te.set_text(port)

        ssl_enabled = self.conf.get_general_option(NIConfig.ni_server_enable_ssl)
        if ssl_enabled is not None:
            try:
                ssl_enabled_bool = bool(ssl_enabled)
            except:
                ssl_enabled_bool = True
            self.enable_encryption_cb.set_active(ssl_enabled_bool)
        else:
            self.enable_encryption_cb.set_active(True)


    def validate_auth_window(self):

        # Find the missing fields
        missing_fields = []
        username = self.username_te.get_text()
        if len(username) is 0:
            missing_fields.append('Username')
        password = self.password_te.get_text()
        if len(password) is 0:
            missing_fields.append('Password')
        host = self.host_te.get_text()
        if len(host) is 0:
            missing_fields.append('Host')
        port = self.port_te.get_text()
        if len(port) is 0:
            missing_fields.append('Port')

        # We found some missing fields
        error_secondary_title = None
        error_msg = None
        if len(missing_fields) > 0:
            error_secondary_title = 'Incomplete form'
            error_msg = 'The following fields are missing:\n'
            for missing_field in missing_fields:
                error_msg += ' - %s \n' % missing_field
            self.show_auth_state_error(error_msg, error_secondary_title)
            return False

        # Make sure the port number is an integer
        try:
            port_int = int(port)
        except:
            error_secondary_title = 'Invalid type'
            error_msg = 'The Port field requires a valid integer port number'
            self.show_auth_state_error(error_msg, error_secondary_title)
            return False

        return True


    def init_events_view(self):
        builder = gtk.Builder()
        builder.add_from_file(ni_events_view_file)
        self.events_view_manager = EventsViewManager(builder, self)
        self.events_view = builder.get_object('events_view_top')
        self.events_view.unparent()
        self.ni_notebook.insert_page(self.events_view,\
                                     gtk.Label('Network Events'), 0)


    def init_hosts_view(self):
        builder = gtk.Builder()
        builder.add_from_file(ni_hosts_view_file)
        self.hosts_view_manager = HostsViewManager(builder, self)
        self.hosts_view = builder.get_object('hosts_view_top')
        self.hosts_view.unparent()
        self.ni_notebook.insert_page(self.hosts_view,\
                                     gtk.Label('Network Hosts'), 1)
        self.hosts_view_manager.add_host_detail_view(ReportsHostsView(self))


    def init_event_window(self):
        self.event_window_manager =\
                EventWindowManager(ni_event_window_file, self)


    def event_show_request(self, notification, parent_window):
        if self.event_window_manager is not None:
            self.event_window_manager.show_event(notification, parent_window)
            cont = self.event_window_manager.get_module_container()
            label = self.event_window_manager.get_module_label()
            self.emit('show-event-details', notification, cont, label)


    def set_login_state(self):
        """ Only shows the authentication window """
        self.auth_window.show()


    def set_run_state(self):
        """ Application running in full mode (after login) """
        self.logged_in = True
        self.auth_window.destroy()
        
        self.main_window.show()


    def add_events_view_notification(self, notification):
        """ Shows the notification in the Events Tree View """
        self.events_view_manager.add_notification(notification)


    def set_protocols(self, protocols):
        """ Sets the protocols that will be shown in the GUI """
        self.events_view_manager.set_protocols(protocols)


    def set_hostnames(self, hostnames):
        """ Sets the hostnames that will be shown in the GUI """
        self.events_view_manager.set_hosts(hostnames)
        self.hosts_view_manager.set_hosts(hostnames)


    def set_ips(self, ips):
        """ Sets the IP addresses that will be shown in the GUI """
        self.events_view_manager.set_ips(ips)
        self.hosts_view_manager.set_ips(ips)


    # Login state handlers

    def on_auth_window_close_button_clicked(self, button):
        self.emit('shutdown')


    def on_auth_window_login_button_clicked(self, button):
        if self.validate_auth_window():
            username = self.username_te.get_text()
            password = self.password_te.get_text()
            host = self.host_te.get_text()
            port = int(self.port_te.get_text())
            enable_ssl = self.enable_encryption_cb.get_active()
            self.emit('login', username, password, host, port, enable_ssl)


    def on_auth_window_destroyed(self, auth_window):
        if not self.logged_in:
            self.emit('shutdown')


    def on_main_window_destroyed(self, main_window):
        self.emit('shutdown')