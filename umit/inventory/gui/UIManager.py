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
import time
import traceback
from copy import copy

from umit.inventory.gui.Configs import NIConfig
from umit.inventory.common import NotificationTypes


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
        # Emitted when the user wants to subscribe with the given options.
        # Parameters: protocol, hosts (list), types (list)
        "subscribe": (gobject.SIGNAL_RUN_FIRST,
                      gobject.TYPE_NONE,
                      (str, gobject.TYPE_PYOBJECT, gobject.TYPE_PYOBJECT)),
        # Emitted when the user wants to unsubscribe.
        "unsubscribe": (gobject.SIGNAL_RUN_FIRST,
                        gobject.TYPE_NONE,
                        ()),
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
                                         flags=gtk.DIALOG_MODAL,\
                                         buttons=gtk.BUTTONS_OK)
        error_dialog.set_property('text', error_second_title)
        error_dialog.set_title('Authentication Error')
        error_dialog.set_property('secondary-text', error_msg)
        error_dialog.connect('response', self.on_dialog_response)
        error_dialog.show()


    def show_run_state_error(self, error_msg, error_second_title):
        error_dialog = gtk.MessageDialog(parent=self.main_window,\
                                         type=gtk.MESSAGE_ERROR,\
                                         buttons=gtk.BUTTONS_OK)
        error_dialog.set_property('text', error_second_title)
        error_dialog.set_title('Runtime Error')
        error_dialog.set_property('secondary-text', error_msg)
        error_dialog.connect('response', self.on_dialog_response)
        error_dialog.show()


    def on_dialog_response(self, dialog, response_id):
        dialog.destroy()


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

    events_shown_options = {'Most Recent 25' : 25,\
                            'Most Recent 50' : 50,\
                            'Most Recent 75' : 75,\
                            'Most Recent 100' : 100}

    TREE_MODEL_COL_HOST = 0
    TREE_MODEL_COL_TYPE = 1
    TREE_MODEL_COL_TIME = 2
    TREE_MODEL_COL_PROT = 3
    TREE_MODEL_COL_DESC = 4
    TREE_MODEL_COL_NOTIF_OBJ = 5

    ALL_PROTOCOLS_SHOWN = 'All'


    def __init__(self, builder, ui_manager):
        gobject.GObject.__init__(self)
        self.events_model = None
        self.ui_manager = ui_manager
        
        # Get objects
        self.events_view = builder.get_object('events_view_top')
        self.events_tree_view = builder.get_object('events_tree_view')
        self.find_events_button = builder.get_object('find_events_button')
        self.receive_events_button = builder.get_object('receive_events_button')
        self.filter_button = builder.get_object('filter_button')
        self.source_host_cbox = builder.get_object('source_host_cbox')
        self.events_shown_cbox = builder.get_object('events_shown_cbox')
        self.protocols_shown_cbox = builder.get_object('protocols_shown_cbox')
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
        self.cb_map = {NotificationTypes.info : self.info_cb,\
                       NotificationTypes.warning : self.warning_cb,\
                       NotificationTypes.recovery : self.recovery_cb,\
                       NotificationTypes.security : self.security_cb,\
                       NotificationTypes.critical : self.critical_cb,\
                       NotificationTypes.unknown : self.unknown_cb}

        # Filter options
        self.events_shown = 0
        self.protocol_shown = self.ALL_PROTOCOLS_SHOWN
        self.hosts_shown = []
        self.types_shown = []

        self.init_events_shown()
        self.init_tree_view()
        self.init_handlers()


    def init_events_shown(self):
        self.events_shown = 0
        self.events_shown_model = gtk.ListStore(gobject.TYPE_STRING)
        cell = gtk.CellRendererText()
        self.events_shown_cbox.pack_start(cell, True)
        self.events_shown_cbox.add_attribute(cell, 'text', 0)
        for option_key in self.events_shown_options.keys():

            iter = self.events_shown_model.append()
            self.events_shown_model.set(iter, 0, option_key)
            if self.events_shown is 0:
                self.events_shown = self.events_shown_options[option_key]
        self.events_shown_cbox.set_active(0)
        self.events_shown_cbox.set_model(self.events_shown_model)


    def set_protocols(self, protocols):
        self.protocols_model = gtk.ListStore(gobject.TYPE_STRING)
        cell = gtk.CellRendererText()
        self.protocols_shown_cbox.pack_start(cell, True)
        self.protocols_shown_cbox.add_attribute(cell, 'text', 0)
        iter = self.protocols_model.append()
        self.protocols_model.set(iter, 0, self.ALL_PROTOCOLS_SHOWN)
        for protocol in protocols:
            iter = self.protocols_model.append()
            self.protocols_model.set(iter, 0, protocol)
        self.protocols_shown_cbox.set_active(0)
        self.protocols_shown_cbox.set_model(self.protocols_model)


    def add_notification(self, notification):
        # Not initialized the GUI yet
        if self.events_model is None:
            return

        # Get the fields
        try:
            hostname = str(notification['hostname'])
            ipv4 = str(notification['source_host_ipv4'])
            ipv6 = str(notification['source_host_ipv6'])
            notif_type = str(notification['event_type'])
            protocol = str(notification['protocol'])
            timestamp = float(notification['timestamp'])
            short_desc = str(notification['short_description'])
        except:
            traceback.print_exc()
            return

        # Format the time
        notif_time = time.ctime(timestamp)

        # Format the source_host
        source_host = hostname + ' '
        if ipv4 is not '':
            source_host += '(%s)' % ipv4
        elif ipv6 is not '':
            source_host += '(%s)' % ipv6

        iter = self.events_model.prepend()

        self.events_model.set(iter,\
                              self.TREE_MODEL_COL_HOST, copy(source_host),\
                              self.TREE_MODEL_COL_TYPE, copy(notif_type),\
                              self.TREE_MODEL_COL_TIME, copy(notif_time),\
                              self.TREE_MODEL_COL_PROT, copy(protocol),\
                              self.TREE_MODEL_COL_DESC, copy(short_desc),\
                              self.TREE_MODEL_COL_NOTIF_OBJ, copy(notification))


    @staticmethod
    def tree_model_visible_func(model, iter, user_data):
        events_view_manager = user_data

        # TODO host data
        notif_type = model.get_value(iter, EventsViewManager.TREE_MODEL_COL_TYPE)
        protocol = model.get_value(iter, EventsViewManager.TREE_MODEL_COL_PROT)

        # TODO look into this
        if notif_type is None or protocol is None:
            return False
        
        # Test the type
        if events_view_manager.types_shown is not []:
            if not events_view_manager.cb_map[notif_type].get_active():
                return False

        # TODO Test the host

        # Test the protocol
        if events_view_manager.protocol_shown != 'All':
            if not events_view_manager.protocol_shown != protocol:
                return False

        return True


    def tree_view_col_data_func(self, column, cell, model, iter, model_col):
        col_text = model.get_value(iter, model_col)
        row_type = model.get_value(iter, self.TREE_MODEL_COL_TYPE)
        cell.set_property('text', col_text)

        if row_type == NotificationTypes.critical:
            cell.set_property('background', '#B50D0D')
            cell.set_property('foreground', '#FFFFFF')
        elif row_type == NotificationTypes.warning:
            cell.set_property('background', '#DB5A5A')
            cell.set_property('foreground', '#FFFFFF')
        else:
            cell.set_property('background-set', False)
            cell.set_property('foreground-set', False)


    def init_tree_view(self):
        """
        Tree View columns: Source Host, Type, Time, Protocol, Short Description.
        """
        # Init model and it's filter
        self.events_model = gtk.ListStore(gobject.TYPE_STRING,\
                gobject.TYPE_STRING, gobject.TYPE_STRING,\
                gobject.TYPE_STRING, gobject.TYPE_STRING,\
                gobject.TYPE_PYOBJECT)
        self.events_filter_model = self.events_model.filter_new()
        self.events_filter_model.set_visible_func(EventsViewManager.tree_model_visible_func, self)

        # Init tree view
        self.events_tree_view.set_model(self.events_filter_model)

        # 1. Source Host Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Source Host', cell)
        col.set_min_width(150)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_HOST)
        self.events_tree_view.append_column(col)

        # 2. Type Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Event Type', cell)
        col.set_min_width(100)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_TYPE)
        self.events_tree_view.append_column(col)

        # 3. Time Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Time', cell)
        col.set_min_width(140)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_TIME)
        self.events_tree_view.append_column(col)

        # 4. Protocol Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Protocol', cell)
        col.set_min_width(110)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_PROT)
        self.events_tree_view.append_column(col)

        # 5. Short Description Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Short Description', cell)
        col.set_min_width(250)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_DESC)
        self.events_tree_view.append_column(col)


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
        #TODO
        pass


    def on_receive_events_button_toggled(self, receive_events_button):
        if receive_events_button.get_active():
            self.ui_manager.emit('subscribe', self.protocol_shown,\
                                 self.hosts_shown, self.types_shown)
        else:
            self.ui_manager.emit('unsubscribe')


    def on_filter_button_clicked(self, filter_button):
        # Get the filtered types
        self.types_shown = []
        if not self.all_cb.get_active():
            for notif_type in self.cb_map.keys():
                if self.cb_map[notif_type].get_active():
                    self.types_shown.append(notif_type)

        # Get the filtered hosts
        # TODO
        self.hosts_shown = []

        # Get the filtered protocol
        iter = self.protocols_shown_cbox.get_active_iter()
        self.protocol_shown = self.protocols_model.get_value(iter, 0)

        # Get the filtered events shown
        iter = self.events_shown_cbox.get_active_iter()
        events_shown_str = self.events_shown_model.get_value(iter, 0)
        self.events_shown = self.events_shown_options[events_shown_str]

        self.events_filter_model.refilter()

        self.ui_manager.emit('subscribe', self.protocol_shown,\
                             self.hosts_shown, self.types_shown)


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