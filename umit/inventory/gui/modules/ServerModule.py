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

from umit.inventory.gui.Module import Module
from umit.inventory.gui.ServerCommunicator import SetConfigsRequest

import gtk
import gobject
import os
import traceback
from copy import copy

#TODO refactoring paths
pixbuf_paths = os.path.join('umit', 'inventory', 'gui', 'pixmaps')
server_logo = os.path.join(pixbuf_paths, 'server_config.png')

class ServerModule(Module):

    logging_levels_list = ['debug', 'info', 'warning', 'error', 'critical']

    def __init__(self, ui_manager, shell):
        Module.__init__(self, ui_manager, shell)
        self.configs = {}
        self.pending_configs = None

        # If the configurations are present and valid
        self.valid_configs = False


    def set_configs(self, configs):
        self.configs = configs
        self.pending_configs = None

        # Parse the configs
        try:
            general_configs = configs['GeneralSection']
            db_configs = configs['Database']

            # General configs
            self.log_path = general_configs['log_path']
            self.log_level = general_configs['log_level']
            self.interface_port = general_configs['interface_port']
            self.force_interface_encrypt =\
                    general_configs['force_interface_encrypt']

            # Database configs
            self.db_host = db_configs['host']
            self.db_port = db_configs['port']
            self.db_username = db_configs['username']
            self.db_password = db_configs['password']
            self.db_store_notifications = db_configs['store_notifications']

            self.valid_configs = True
        except:
            traceback.print_exc()
            self.valid_configs = False


    def add_configs_ui(self, config_window_manager):
        if not self.valid_configs:
            return
        
        self.config_widget = None
        self._build_config_objects()
        self._init_config_values()
        self._init_config_handlers()

        pixbuf = gtk.gdk.pixbuf_new_from_file(server_logo)
        config_window_manager.add_config_page(pixbuf,\
                'Notifications Server', self.config_widget)


    def _build_config_objects(self):
        file_name = self.ui_manager.glade_files['server_config']
        builder = gtk.Builder()
        builder.add_from_file(file_name)
        self.config_widget = builder.get_object('ni_server_config_top')
        self.config_widget.unparent()
        self.port_entry = builder.get_object('port_entry')
        self.force_encryption_cb = builder.get_object('force_encryption_cb')
        self.log_path_entry = builder.get_object('log_path_entry')
        self.log_level_combo = builder.get_object('log_level_combo')
        self.db_host_entry = builder.get_object('db_host_entry')
        self.db_port_entry = builder.get_object('db_port_entry')
        self.db_username_entry = builder.get_object('db_username_entry')
        self.db_password_entry = builder.get_object('db_password_entry')
        self.store_notifications_cb =\
                builder.get_object('store_notifications_cb')
        self.apply_button = builder.get_object('apply_button')
        self.restore_button = builder.get_object('restore_button')

        cell = gtk.CellRendererText()
        self.log_level_combo.pack_start(cell, True)
        self.log_level_combo.add_attribute(cell, 'text', 0)


    def _init_config_values(self):
        self.port_entry.set_text(self.interface_port)
        self.log_path_entry.set_text(self.log_path)
        self.db_host_entry.set_text(self.db_host)
        self.db_port_entry.set_text(self.db_port)
        self.db_username_entry.set_text(self.db_username)
        self.db_password_entry.set_text(self.db_password)

        self.force_encryption_cb.set_active(bool(self.force_interface_encrypt))
        self.store_notifications_cb.set_active(bool(self.db_store_notifications))

        self.port_entries_valid = {self.db_port_entry : True,\
                                   self.port_entry : True}

        # Init combo box
        self.log_level_model = gtk.ListStore(gobject.TYPE_STRING)
        for logging_level in self.logging_levels_list:
            iter = self.log_level_model.append()
            self.log_level_model.set(iter, 0, logging_level)

        self.log_level_combo.set_model(self.log_level_model)
        if self.log_level in self.logging_levels_list:
            self.log_level_combo.set_active(\
                self.logging_levels_list.index(self.log_level))
        

    def _init_config_handlers(self):
        self.port_entry.connect('changed', self.on_port_entry_changed)
        self.db_port_entry.connect('changed', self.on_port_entry_changed)
        self.restore_button.connect('clicked', self.on_restore_button_clicked)
        self.apply_button.connect('clicked', self.on_apply_button_clicked)


    # Config window handlers

    def on_port_entry_changed(self, entry):
        value = entry.get_text()

        # Allow an empty string or an integer
        if value is not '':
            try:
                int_value = int(value)
            except:
                entry.set_icon_from_stock(gtk.ENTRY_ICON_SECONDARY,\
                                          gtk.STOCK_DIALOG_ERROR)
                entry.set_icon_tooltip_text(gtk.ENTRY_ICON_SECONDARY,\
                                            'Requires an integer')
                self.port_entries_valid[entry] = False
                self.apply_button.set_sensitive(False)
                return

        self.port_entries_valid[entry] = True
        entry.set_icon_from_stock(gtk.ENTRY_ICON_SECONDARY, None)

        for valid_entry_value in self.port_entries_valid.values():
            if not valid_entry_value:
                return
        self.apply_button.set_sensitive(True)


    def on_restore_button_clicked(self, restore_button):
        self._init_config_values()


    def on_apply_button_clicked(self, apply_button):
        # Get the values
        self.db_host = self.db_host_entry.get_text()
        self.db_port = self.db_port_entry.get_text()
        self.db_username = self.db_username_entry.get_text()
        self.db_password = self.db_password_entry.get_text()
        self.interface_port = self.port_entry.get_text()
        self.force_interface_encrypt = self.force_encryption_cb.get_active()
        self.db_store_notifications = self.store_notifications_cb.get_active()
        self.log_path = self.log_path_entry.get_text()

        iter = self.log_level_combo.get_active_iter()
        self.log_level = self.log_level_model.get_value(iter, 0)

        # Parse the configs into a dictionary
        configs = dict()
        general_section = dict()
        database = dict()
        general_section['interface_port'] = self.interface_port
        general_section['force_interface_encrypt'] = self.force_interface_encrypt
        general_section['log_level'] = self.log_level
        general_section['log_path'] = self.log_path
        database['username'] = self.db_username
        database['password'] = self.db_password
        database['host'] = self.db_host
        database['port'] = self.db_port
        database['store_notifications'] = self.db_store_notifications
        configs['GeneralSection'] = general_section
        configs['Database'] = database
        self.pending_configs = configs

        # Send the configs to the server
        self.shell.send_request(SetConfigsRequest(self.shell.get_username(),\
                self.shell.get_password(), configs, self.send_configs_callback))


    def send_configs_callback(self, failed):
        if not failed:
            self.set_configs(copy(self.pending_configs))
        else:
            self.set_configs(copy(self.configs))
        

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