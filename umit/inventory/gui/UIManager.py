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

# TODO needs refactoring
glade_files_path = os.path.join('umit', 'inventory', 'gui', 'glade_files')
ni_main_window_file = os.path.join(glade_files_path, 'ni_main.glade')
ni_auth_window_file = os.path.join(glade_files_path, 'ni_auth_window.glade')
ni_events_view_file = os.path.join(glade_files_path, 'ni_events_view.glade')


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
        self.init_main_window()
        self.init_auth_window()
        self.init_events_view()


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
                                         buttons=gtk.BUTTONS_OK)
        error_dialog.set_property('text', error_second_title)
        error_dialog.set_title('Authentication Error')
        error_dialog.set_property('secondary-text', error_msg)
        error_dialog.run()
        error_dialog.destroy()


    def show_run_state_error(self, error_msg, error_second_title):
        error_dialog = gtk.MessageDialog(parent=self.main_window,\
                                         type=gtk.MESSAGE_ERROR,\
                                         buttons=gtk.BUTTONS_OK)
        error_dialog.set_property('text', error_second_title)
        error_dialog.set_title('Runtime Error')
        error_dialog.set_property('secondary-text', error_msg)
        error_dialog.run()
        error_dialog.destroy()


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
        self.events_view_manager = EventsViewManager(builder)
        self.events_view = builder.get_object('events_view_top')
        self.events_view.unparent()
        self.ni_notebook.insert_page(self.events_view,\
                                     gtk.Label('Network Events'), 0)


    def set_login_state(self):
        """ Only shows the authentication window """
        self.auth_window.show()


    def set_run_state(self):
        """ Application running in full mode (after login) """
        self.logged_in = True
        self.auth_window.destroy()
        
        self.main_window.show()


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



class EventsViewManager(gobject.GObject):

    events_shown_options = {25 : 'Most Recent 25',\
                            50 : 'Most Recent 50',\
                            75 : 'Most Recent 75',\
                            100 : 'Most Recent 100'}


    def __init__(self, builder):
        gobject.GObject.__init__(self)

        # Get objects
        self.events_view = builder.get_object('events_view_top')
        self.events_tree_view = builder.get_object('events_tree_view')
        self.find_events_button = builder.get_object('find_events_button')
        self.receive_events_button = builder.get_object('receive_events_button')
        self.filter_button = builder.get_object('filter_button')
        self.source_host_cbox = builder.get_object('source_host_cbox')
        self.events_shown_cbox = builder.get_object('events_shown_cbox')
        self.all_cb = builder.get_object('all_checkbox')
        self.info_cb = builder.get_object('info_checkbox')
        self.recovery_cb = builder.get_object('recovery_checkbox')
        self.warning_cb = builder.get_object('warning_checkbox')
        self.security_cb = builder.get_object('security_checkbox')
        self.critical_cb = builder.get_object('critical_checkbox')
        self.unknown_cb = builder.get_object('unknown_checkbox')

        # For faster checking/unchecking
        self.cb_list = [self.info_cb, self.recovery_cb, self.warning_cb,\
                        self.security_cb, self.critical_cb, self.unknown_cb]

        self.init_events_shown()
        self.init_handlers()


    def init_events_shown(self):
        self.events_shown = 0
        self.events_shown_model = gtk.ListStore(gobject.TYPE_STRING)
        cell = gtk.CellRendererText()
        self.events_shown_cbox.pack_start(cell, True)
        self.events_shown_cbox.add_attribute(cell, 'text', 0)
        for option_key in self.events_shown_options.keys():
            option_val = self.events_shown_options[option_key]

            iter = self.events_shown_model.append()
            print option_val
            self.events_shown_model.set(iter, 0, option_val)
            if self.events_shown is 0:
                self.events_shown = option_key
        self.events_shown_cbox.set_active(0)
        self.events_shown_cbox.set_model(self.events_shown_model)


    def init_handlers(self):
        self.find_events_button.connect('clicked',\
                self.on_find_events_button_clicked)
        self.receive_events_button.connect('toggled',\
                self.on_receive_events_button_toggled)
        self.filter_button.connect('clicked',\
                self.on_filter_button_clicked)
        self.all_cb.connect('toggled', self.on_all_cb_toggled)
        self.info_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.warning_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.recovery_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.critical_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.security_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.unknown_cb.connect('toggled', self.on_not_all_cb_toggled)


    def checkbuttons_active(self):
        for cb in self.cb_list:
            if not cb.get_active():
                return False
        return True


    def on_find_events_button_clicked(self, find_events_button):
        pass


    def on_receive_events_button_toggled(self, receive_events_button):
        pass


    def on_filter_button_clicked(self, filter_button):
        pass


    def on_all_cb_toggled(self, all_cb):
        active = all_cb.get_active()

        if active:
            for cb in self.cb_list:
                cb.set_active(True)
        elif self.checkbuttons_active():
            for cb in self.cb_list:
                cb.set_active(False)


    def on_not_all_cb_toggled(self, cb):
        active = cb.get_active()
        if not active:
            self.all_cb.set_active(False)
        elif self.checkbuttons_active():
            self.all_cb.set_active(True)