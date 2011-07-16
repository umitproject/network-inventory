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
import datetime

from umit.inventory.gui.Configs import NIConfig
from umit.inventory.common import NotificationTypes


# TODO needs refactoring
glade_files_path = os.path.join('umit', 'inventory', 'gui', 'glade_files')
ni_main_window_file = os.path.join(glade_files_path, 'ni_main.glade')
ni_auth_window_file = os.path.join(glade_files_path, 'ni_auth_window.glade')
ni_events_view_file = os.path.join(glade_files_path, 'ni_events_view.glade')
ni_event_window_file = os.path.join(glade_files_path, 'ni_event_window.glade')
ni_search_window_file = os.path.join(glade_files_path, 'ni_search_window.glade')
ni_time_date_picker_file = os.path.join(glade_files_path,\
                                        'ni_time_date_picker.glade')


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


    def init_event_window(self):
        self.event_window_manager =\
                EventWindowManager(ni_event_window_file, self)


    def event_show_request(self, notification):
        if self.event_window_manager is not None:
            self.event_window_manager.show_event(notification, self.main_window)
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


    def set_ips(self, ips):
        """ Sets the IP addresses that will be shown in the GUI """
        self.events_view_manager.set_ips(ips)


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



    ALL_PROTOCOLS_SHOWN = 'All'


    def __init__(self, builder, ui_manager):
        gobject.GObject.__init__(self)
        self.events_model = None
        self.ui_manager = ui_manager
        
        # Get objects
        self.events_view = builder.get_object('events_view_top')
        self.events_widget_container =\
                builder.get_object('events_widget_container')
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

        # Used for the window that is shown when the Find button is pressed
        self.search_window_manager = SearchWindowManager(self.ui_manager)

        # The widget where the events will be shown
        self.events_widget = EventsViewWidget(self.ui_manager,\
                self.tree_model_visible_func, self)
        self.events_widget_container.add(self.events_widget)
        self.events_widget.show()

        # Filter options
        self.events_shown = 0
        self.protocol_shown = self.ALL_PROTOCOLS_SHOWN
        self.hosts_shown = []
        self.types_shown = []

        self.init_events_shown()
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


    def add_notification(self, notification):
        self.events_widget.add_notification(notification)

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

        self.search_window_manager.set_protocols(protocols)


    def set_hosts(self, hosts):
        self.hosts_model = gtk.ListStore(gobject.TYPE_STRING)
        cell = gtk.CellRendererText()
        self.source_host_cbox.pack_start(cell, True)
        self.source_host_cbox.add_attribute(cell, 'text', 0)
        for host in hosts:
            iter = self.hosts_model.append()
            self.hosts_model.set(iter, 0, host)
        self.source_host_cbox.set_model(self.hosts_model)

        self.search_window_manager.set_hosts(hosts)


    def set_ips(self, ips):
        self.search_window_manager.set_ips(ips)


    @staticmethod
    def tree_model_visible_func(model, iter, user_data):
        events_view_manager = user_data

        # TODO host data
        notif_type = model.get_value(iter, EventsViewWidget.TREE_MODEL_COL_TYPE)
        protocol = model.get_value(iter, EventsViewWidget.TREE_MODEL_COL_PROT)

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
        if not self.search_window_manager.window_is_shown():
            self.search_window_manager.show_window(self.ui_manager.main_window)


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

        self.events_widget.refilter()

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



class EventWindowManager:

    DETAILS_TREE_COL_KEY = 0
    DETAILS_TREE_COL_VALUE = 1


    def __init__(self, glade_file, ui_manager):
        self.ui_manager = ui_manager
        self.glade_file = glade_file

    def _get_objects(self):
        builder = gtk.Builder()
        builder.add_from_file(self.glade_file)

        # Get the objects
        self.event_window = builder.get_object('event_window')
        self.host_label = builder.get_object('host_label')
        self.type_label = builder.get_object('type_label')
        self.time_label = builder.get_object('time_label')
        self.ip_label = builder.get_object('ip_label')
        self.details_expander = builder.get_object('details_expander')
        self.module_expander = builder.get_object('module_expander')
        self.description_text_view = builder.get_object('description_text_view')
        self.details_tree_view = builder.get_object('details_tree_view')
        self.module_specific_label = builder.get_object('module_specific_label')
        self.module_specific_zone = builder.get_object('module_specific_zone')
        self.module_specific_container =\
            builder.get_object('module_specific_container')


    def show_event(self, event, parent_window):
        """
        Called when we should show the Event window for the given event.
        event: The Notification object for which we want to show the window.
        parent_window: The parent window for the event window.
        """
        # Load the window
        try:
            self._get_objects()
        except:
            traceback.print_exc()
            return

        # Get the needed details
        try:
            hostname = event['hostname']
            ipv4_addr = event['source_host_ipv4']
            ipv6_addr = event['source_host_ipv6']
            event_type = event['event_type']
            timestamp = float(event['timestamp'])
            description = event['description']
        except:
            traceback.print_exc()
            return

        # Set the values for the labels
        self.host_label.set_markup(self.format_host_label(hostname))
        self.time_label.set_markup(self.format_time_label(timestamp))
        self.ip_label.set_markup(self.format_ip_label(ipv4_addr, ipv6_addr))
        self.type_label.set_markup(self.format_type_label(event_type))

        # Set the value for the text view
        buffer = self.description_text_view.get_buffer()
        buffer.set_text(description)

        # Hide the module-specific zone until we get a request to show
        # a widget in it
        self.module_specific_zone.hide()

        # Initialize the fields TreeView
        self._init_details_tree_view(event)
        
        # Show the window
        self.event_window.set_transient_for(parent_window)
        self.event_window.set_destroy_with_parent(True)
        self.event_window.show()


    def get_module_container(self):
        return self.module_specific_container


    def get_module_label(self):
        return self.module_specific_label
        

    def _init_details_tree_view(self, event):
        # Init model
        details_model = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING)
        for event_key in event.keys():
            field_value = str(event[event_key])
            field_key = '<b>%s</b>' % event_key
            iter = details_model.append()
            details_model.set(iter,\
                              self.DETAILS_TREE_COL_KEY, copy(field_key),\
                              self.DETAILS_TREE_COL_VALUE, copy(field_value))
        self.details_tree_view.set_model(details_model)
    
        # 1. Field Name Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Field Name', cell,\
                                 markup=self.DETAILS_TREE_COL_KEY)
        col.set_min_width(200)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        self.details_tree_view.append_column(col)

        # 2. Type Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Field Name', cell,\
                                 markup=self.DETAILS_TREE_COL_VALUE)
        col.set_min_width(200)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        self.details_tree_view.append_column(col)


    @staticmethod
    def format_host_label(hostname):
        if hostname in ('', None):
            hostname = '[Undefined]'
        return '<b>Source Host</b>: %s' % hostname


    @staticmethod
    def format_time_label(timestamp):
        time_str = time.ctime(timestamp)
        return '<b>Time</b>: %s' % time_str


    @staticmethod
    def format_ip_label(ipv4_addr, ipv6_addr):
        if ipv4_addr not in ('', None):
            ip_addr = ipv4_addr
        elif ipv6_addr not in ('', None):
            ip_addr = ipv6_addr
        else:
            ip_addr = '[Undefined]'
        return '<b>IP Address</b>: %s' % ip_addr


    @staticmethod
    def format_type_label(event_type):
        if event_type == NotificationTypes.critical:
            color = '#B50D0D'
        elif event_type == NotificationTypes.warning:
            color = '#DB5A5A'
        else:
            color = 'black'

        return '<b>Type: <span foreground=\'%s\'>%s</span></b>' %\
                (color, event_type)



class SearchWindowManager:

    def __init__(self, ui_manager):
        self.ui_manager = ui_manager
        self.window_shown = False
        self.protocols = None
        self.hosts = None
        self.ips = None
        self.protocols_model = None
        self.hosts_model = None
        self.ips_model = None

        self.time_picker_shown = False


    def set_ips(self, ips):
        self.ips_model = gtk.ListStore(gobject.TYPE_STRING)
        for ip in ips:
            iter = self.ips_model.append()
            self.ips_model.set(iter, 0, ip)
        self.ips = ips


    def set_hosts(self, hosts):
        self.hosts_model = gtk.ListStore(gobject.TYPE_STRING)
        for host in hosts:
            iter = self.hosts_model.append()
            self.hosts_model.set(iter, 0, host)
        self.hosts = hosts


    def set_protocols(self, protocols):
        self.protocols_model = gtk.ListStore(gobject.TYPE_STRING)
        iter = self.protocols_model.append()
        self.protocols_model.set(iter, 0, 'All')
        for protocol in protocols:
            iter = self.protocols_model.append()
            self.protocols_model.set(iter, 0, protocol)
        self.protocols = protocols


    def window_is_shown(self):
        return self.window_shown


    def show_window(self, parent_window):
        self.parent_window = parent_window
        self.window_shown = True
        builder = gtk.Builder()
        self.search_window = builder.add_from_file(ni_search_window_file)
        self._build_objects(builder)
        self.search_window.set_transient_for(parent_window)
        self.search_window.set_destroy_with_parent(True)
        self.search_window.show()


    def _build_objects(self, builder):
        self.search_window = builder.get_object('search_window')
        self.hostname_combo = builder.get_object('hostname_combo')
        self.ip_combo = builder.get_object('ip_combo')
        self.protocol_combo = builder.get_object('protocol_combo')
        self.start_time_button = builder.get_object('start_time_button')
        self.end_time_button = builder.get_object('end_time_button')
        self.info_cb = builder.get_object('info_checkbox')
        self.recovery_cb = builder.get_object('recovery_checkbox')
        self.warning_cb = builder.get_object('warning_checkbox')
        self.security_cb = builder.get_object('security_checkbox')
        self.critical_cb = builder.get_object('critical_checkbox')
        self.unknown_cb = builder.get_object('unknown_checkbox')

        self._init_handlers()
        self._init_values()
        self._init_widgets()


    def _init_handlers(self):
        self.search_window.connect('destroy', self.on_window_destroyed)
        self.hostname_combo.connect('changed', self.on_hostname_changed)
        self.ip_combo.connect('changed', self.on_ip_changed)
        self.protocol_combo.connect('changed', self.on_protocol_changed)
        self.start_time_button.connect('clicked', self.on_time_button_clicked,\
                                       'start_time')
        self.end_time_button.connect('clicked', self.on_time_button_clicked,\
                                     'end_time')
        self.info_cb.connect('toggled', self.on_type_cb_toggled)
        self.recovery_cb.connect('toggled', self.on_type_cb_toggled)
        self.warning_cb.connect('toggled', self.on_type_cb_toggled)
        self.critical_cb.connect('toggled', self.on_type_cb_toggled)
        self.security_cb.connect('toggled', self.on_type_cb_toggled)
        self.unknown_cb.connect('toggled', self.on_type_cb_toggled)

        # Mapping type buttons to their string values
        self.type_map = {self.info_cb : NotificationTypes.info,\
                         self.recovery_cb : NotificationTypes.recovery,\
                         self.warning_cb : NotificationTypes.warning,\
                         self.critical_cb : NotificationTypes.critical,\
                         self.security_cb : NotificationTypes.security,\
                         self.unknown_cb : NotificationTypes.unknown}


    def _init_values(self):
        self.hostname = None
        self.ip_addr = None
        self.protocol = None
        self.start_time = None
        self.end_time = None
        self.shown_events_types = [NotificationTypes.info,\
            NotificationTypes.warning, NotificationTypes.recovery,\
            NotificationTypes.critical, NotificationTypes.security,\
            NotificationTypes.unknown]


    def _init_widgets(self):
        self.ip_combo.set_model(self.ips_model)
        ip_combo_entry = self.ip_combo.get_child()
        ip_entry_completion = gtk.EntryCompletion()
        ip_entry_completion.set_model(self.ips_model)
        ip_entry_completion.set_text_column(0)
        ip_entry_completion.set_inline_completion(True)
        ip_combo_entry.set_completion(ip_entry_completion)
        
        self.hostname_combo.set_model(self.hosts_model)
        host_combo_entry = self.hostname_combo.get_child()
        host_entry_completion = gtk.EntryCompletion()
        host_entry_completion.set_model(self.hosts_model)
        host_entry_completion.set_text_column(0)
        host_entry_completion.set_inline_completion(True)
        host_combo_entry.set_completion(host_entry_completion)

        cell = gtk.CellRendererText()
        self.protocol_combo.pack_start(cell, True)
        self.protocol_combo.add_attribute(cell, 'text', 0)
        self.protocol_combo.set_model(self.protocols_model)
        self.protocol_combo.set_active(0)


    def on_window_destroyed(self, window):
        self.window_shown = False
        if self.time_picker_shown:
            self.time_popup.destroy()


    def on_hostname_changed(self, hostname_combo):
        host_entry = hostname_combo.get_child()
        self.hostname = host_entry.get_text()
        if self.hostname is '':
            self.hostname = None


    def on_ip_changed(self, ip_combo):
        ip_entry = ip_combo.get_child()
        self.ip_addr = ip_entry.get_text()
        if self.ip_addr is '':
            self.ip_addr = None


    def on_protocol_changed(self, protocol_combo):
        iter = protocol_combo.get_active_iter()
        if iter is not None:
            self.protocol = self.protocols_model.get_value(iter, 0)
            if self.protocol == 'All':
                self.protocol = None
        print self.protocol

        
    def on_time_button_clicked(self, time_button, target):
        if self.time_picker_shown:
            self.time_popup.destroy()
        self.time_picker_shown = True

        builder = gtk.Builder()
        builder.add_from_file(ni_time_date_picker_file)
        self.time_popup = builder.get_object('time_date_popup')
        self.date_calendar = builder.get_object('date_calendar')
        self.hour_spin = builder.get_object('hour_spin')
        self.minute_spin = builder.get_object('minute_spin')
        self.second_spin = builder.get_object('second_spin')
        set_button = builder.get_object('set_button')
        reset_button = builder.get_object('reset_button')

        self.time_popup.set_transient_for(self.search_window)

        # Set the position for the time-picker popup
        parent_position = self.search_window.get_position()
        cursor_position = self.search_window.get_pointer()
        self.time_popup.move(parent_position[0] + cursor_position[0],\
                             parent_position[1] + cursor_position[1])

        # Connect the handlers
        self.search_window.connect('focus-out-event',\
                                   self.on_search_window_focus_out)
        self.search_window.connect('button-press-event',\
                                   self.on_search_window_button_press)
        self.time_popup.connect('destroy', self.on_time_popup_destroyed)
        set_button.connect('clicked', self.on_time_set_clicked,\
                           time_button, target)
        reset_button.connect('clicked', self.on_time_reset_clicked,\
                             time_button, target)
        self.time_popup.show()


    def on_time_popup_destroyed(self, time_popup):
        self.time_picker_shown = False


    def on_time_set_clicked(self, set_button, time_button, target):
        # Get the time information
        year, month, day = self.date_calendar.get_date()
        hour = self.hour_spin.get_value_as_int()
        minute = self.minute_spin.get_value_as_int()
        second = self.second_spin.get_value_as_int()

        # Because the returned month is in 0-11 range
        month += 1

        date_time = datetime.datetime(year, month, day, hour, minute, second)
        time_button.set_label(date_time.strftime('%B %d %Y %H:%M:%S'))

        if target == 'start_time':
            self.start_time = time.mktime(date_time.timetuple())
        elif target == 'end_time':
            self.end_time = time.mktime(date_time.timetuple())


    def on_time_reset_clicked(self, reset_button, time_button, target):
        time_button.set_label('Choose time...')
        if target == 'start_time':
            self.start_time = None
        elif target == 'end_time':
            self.end_time = None


    def on_search_window_focus_out(self, search_window, event):
        if not self.time_picker_shown:
            return
        self.time_popup.destroy()


    def on_search_window_button_press(self, search_window, event):
        if not self.time_picker_shown:
            return
        if event.type == gtk.gdk.BUTTON_PRESS:
            self.time_popup.destroy()


    def on_type_cb_toggled(self, type_cb):
        active = type_cb.get_active()
        type_value = self.type_map[type_cb]
        if active and type_value not in self.shown_events_types:
            self.shown_events_types.append(type_value)
        if not active and type_value in self.shown_events_types:
            self.shown_events_types.remove(type_value)



class EventsViewWidget(gtk.TreeView):

    # Model columns
    TREE_MODEL_COL_HOST = 0
    TREE_MODEL_COL_TYPE = 1
    TREE_MODEL_COL_TIME = 2
    TREE_MODEL_COL_PROT = 3
    TREE_MODEL_COL_DESC = 4
    TREE_MODEL_COL_NOTIF_OBJ = 5


    def __init__(self, ui_manager, filter_function=None,\
                 filter_func_user_data=None):
        self.ui_manager = ui_manager
        self.filter_function = filter_function
        self.filter_function_user_data = filter_func_user_data

        gtk.TreeView.__init__(self)
        
        self._init_model()
        self._init_columns()

        self.connect('row-activated', self.on_row_activated)


    def _init_model(self):
        self.model = gtk.ListStore(gobject.TYPE_STRING,\
                gobject.TYPE_STRING, gobject.TYPE_STRING,\
                gobject.TYPE_STRING, gobject.TYPE_STRING,\
                gobject.TYPE_PYOBJECT)
        if self.filter_function is not None:
            self.filter_model = self.model.filter_new()
            self.filter_model.set_visible_func(self.filter_function,\
                self.filter_function_user_data)
            self.set_model(self.filter_model)
        else:
            self.set_model(self.model)


    def _init_columns(self):

        # 1. Source Host Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Source Host', cell)
        col.set_min_width(150)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_HOST)
        self.append_column(col)

        # 2. Type Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Event Type', cell)
        col.set_min_width(100)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_TYPE)
        self.append_column(col)

        # 3. Time Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Time', cell)
        col.set_min_width(140)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_TIME)
        self.append_column(col)

        # 4. Protocol Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Protocol', cell)
        col.set_min_width(110)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_PROT)
        self.append_column(col)

        # 5. Short Description Column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Short Description', cell)
        col.set_min_width(250)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                               self.TREE_MODEL_COL_DESC)
        self.append_column(col)

        
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


    def on_row_activated(self, treeview, path, view_column):
        iter = self.model.get_iter(path)
        notification = self.model.get_value(iter, self.TREE_MODEL_COL_NOTIF_OBJ)
        self.ui_manager.event_show_request(notification)


    def add_notification(self, notification):
        # Not initialized the GUI yet
        if self.model is None:
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

        iter = self.model.prepend()

        self.model.set(iter,\
                       self.TREE_MODEL_COL_HOST, copy(source_host),\
                       self.TREE_MODEL_COL_TYPE, copy(notif_type),\
                       self.TREE_MODEL_COL_TIME, copy(notif_time),\
                       self.TREE_MODEL_COL_PROT, copy(protocol),\
                       self.TREE_MODEL_COL_DESC, copy(short_desc),\
                       self.TREE_MODEL_COL_NOTIF_OBJ, copy(notification))


    def refilter(self):
        if self.filter_function is not None:
            self.filter_model.refilter()
