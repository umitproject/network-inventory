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

import os
import gtk
import gobject
import traceback
from copy import copy


class EMailNotifierModule(Module):

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
            mail_configs = configs['EmailSender']

            self.enabled = mail_configs['enabled']
            if self.enabled in ['True', 'true']:
                self.enabled = True
            else:
                self.enabled = False
            self.host = mail_configs['smtp_server_host']
            self.port = mail_configs['smtp_server_port']
            self.from_address = mail_configs['from_address']
            self.ssl = mail_configs['enable_ssl']
            self.tls = mail_configs['enable_starttls_extension']
            self.enable_html = mail_configs['enable_html']
            self.username = mail_configs['login']
            self.password = mail_configs['password']
            self.to_list = mail_configs['to_list_addresses'].split(',')
            self.send_types = mail_configs['send_for_types'].lower().split(',')
            
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

        email_logo = self.ui_manager.get_pixmap_file_path('mail_config.png')
        pixbuf = gtk.gdk.pixbuf_new_from_file(email_logo)
        config_window_manager.add_config_page(pixbuf,
                'E-Mail Notifier', self.config_widget)


    def _build_config_objects(self):
        file_name = self.ui_manager.get_glade_file_path('ni_email_config.glade')
        builder = gtk.Builder()
        builder.add_from_file(file_name)
        self.config_widget = builder.get_object('email_config_top')
        self.email_config_notebook = builder.get_object('email_config_notebook')
        self.email_config_notebook.remove_page(-1)
        self.config_widget.unparent()
        self.enable_cb = builder.get_object('enable_cb')
        self.username_entry = builder.get_object('username_entry')
        self.password_entry = builder.get_object('password_entry')
        self.host_entry = builder.get_object('host_entry')
        self.port_entry = builder.get_object('port_entry')
        self.ssl_cb = builder.get_object('ssl_cb')
        self.tls_cb = builder.get_object('tls_cb')
        self.info_cb = builder.get_object('info_cb')
        self.warning_cb = builder.get_object('warning_cb')
        self.critical_cb = builder.get_object('critical_cb')
        self.recovery_cb = builder.get_object('recovery_cb')
        self.security_cb = builder.get_object('security_cb')
        self.unknown_cb = builder.get_object('unknown_cb')
        self.send_from_entry = builder.get_object('send_from_entry')
        self.send_to_treeview = builder.get_object('send_to_treeview')
        self.add_button = builder.get_object('add_button')
        self.del_button = builder.get_object('del_button')
        self.del_button.set_sensitive(False)
        self.html_cb = builder.get_object('html_cb')
        self.restore_button = builder.get_object('restore_button')
        self.apply_button = builder.get_object('apply_button')

        self.type_to_cb_map = {'info' : self.info_cb,
                               'warning' : self.warning_cb,
                               'critical' : self.critical_cb,
                               'security' : self.security_cb,
                               'recovery' : self.recovery_cb,
                               'unknown' : self.unknown_cb}

        # Init tree view column
        self.tree_view_cell = gtk.CellRendererText()
        self.tree_view_cell.set_property('editable', True)
        self.tree_view_col = gtk.TreeViewColumn('Send to', self.tree_view_cell)
        self.tree_view_col.set_property('resizable', False)
        self.tree_view_col.add_attribute(self.tree_view_cell, 'text', 0)
        self.send_to_treeview.append_column(self.tree_view_col)

        self.send_to_selection = self.send_to_treeview.get_selection()
        self.send_to_selection.set_mode(gtk.SELECTION_MULTIPLE)


    def _init_config_values(self):
        self.enable_cb.set_active(self.enabled)
        self.username_entry.set_text(self.username)
        self.password_entry.set_text(self.password)
        self.host_entry.set_text(self.host)
        self.port_entry.set_text(self.port)
        self.ssl_cb.set_active(bool(self.ssl))
        self.tls_cb.set_active(bool(self.tls))
        for event_type in self.type_to_cb_map.keys():
            try:
                self.type_to_cb_map[event_type].set_active(
                        event_type in self.send_types)
            except:
                pass
        self.send_from_entry.set_text(self.from_address)
        self.html_cb.set_active(bool(self.enable_html))

        # Init to addresses tree view
        self.send_to_model = gtk.ListStore(gobject.TYPE_STRING)
        self.send_to_treeview.set_headers_visible(False)
        self.send_to_treeview.set_model(self.send_to_model)

        # No address
        if len(self.to_list) == 1 and self.to_list[0] == '':
            return

        for address in self.to_list:
            iter = self.send_to_model.append()
            self.send_to_model.set(iter, 0, address)


    def _init_config_handlers(self):
        self.add_button.connect('clicked', self.on_add_button_clicked)
        self.del_button.connect('clicked', self.on_del_button_clicked)
        self.apply_button.connect('clicked', self.on_apply_button_clicked)
        self.restore_button.connect('clicked', self.on_restore_button_clicked)
        self.send_to_selection.connect('changed',
                self.on_send_to_selection_changed)
        self.port_entry.connect('changed', self.on_port_entry_changed)
        self.tree_view_cell.connect('edited', self.on_tree_view_cell_edited)


    def on_add_button_clicked(self, add_button):
        iter = self.send_to_model.append()
        self.send_to_model.set(iter, 0, '')
        path = self.send_to_model.get_path(iter)
        self.send_to_treeview.set_cursor_on_cell(path, self.tree_view_col,
                                                 self.tree_view_cell, True)


    def on_del_button_clicked(self, del_button):
        model, selected_paths = self.send_to_selection.get_selected_rows()

        selected_rows = list()
        for selected_path in selected_paths:
            selected_rows.append(gtk.TreeRowReference(model, selected_path))
        
        for selected_row in selected_rows:
            path = selected_row.get_path()
            iter = model.get_iter(path)
            model.remove(iter)
            

    def on_apply_button_clicked(self, apply_button):
        # Get the values
        self.enabled = self.enable_cb.get_active()
        self.host = self.host_entry.get_text()
        self.port = self.port_entry.get_text()
        self.from_address = self.send_from_entry.get_text()
        self.ssl = self.ssl_cb.get_active()
        self.tls = self.tls_cb.get_active()
        self.enable_html = self.html_cb.get_active()
        self.username = self.username_entry.get_text()
        self.password = self.password_entry.get_text()
        self.send_types = list()
        for event_type in self.type_to_cb_map.keys():
            if self.type_to_cb_map[event_type].get_active():
                self.send_types.append(event_type)
        iter = self.send_to_model.get_iter_first()
        self.to_list = list()
        while iter is not None:
            address = self.send_to_model.get_value(iter, 0)
            self.to_list.append(address)
            iter = self.send_to_model.iter_next(iter)

        # Parse the values in a config dictionary
        mail_configs = dict()
        mail_configs['enabled'] = self.enabled
        mail_configs['smtp_server_host'] = self.host
        mail_configs['smtp_server_port'] = self.port
        mail_configs['from_address'] = self.from_address
        mail_configs['enable_ssl'] = self.ssl
        mail_configs['enable_starttls_extension'] = self.tls
        mail_configs['enable_html'] = self.enable_html
        mail_configs['login'] = self.username
        mail_configs['password'] = self.password

        mail_configs['to_list_addresses'] = ''
        for address in self.to_list:
            mail_configs['to_list_addresses'] += '%s,' % address
        mail_configs['to_list_addresses'].strip(',')

        mail_configs['send_for_types'] = ''
        for event_type in self.send_types:
            mail_configs['send_for_types'] += '%s,' % event_type
        mail_configs['send_for_types'].strip(',')

        self.pending_configs = dict()
        self.pending_configs['EmailSender'] = mail_configs

        # Send the configs to the server
        self.shell.send_request(SetConfigsRequest(self.shell.get_username(),\
                self.shell.get_password(), self.pending_configs,\
                self.send_configs_callback))


    def send_configs_callback(self, failed):
        if not failed:
            self.set_configs(copy(self.pending_configs))
        else:
            self.set_configs(copy(self.configs))


    def on_restore_button_clicked(self, restore_button):
        self._init_config_values()


    def on_send_to_selection_changed(self, send_to_selection):
        model, selected_rows = send_to_selection.get_selected_rows()

        if len(selected_rows) is 0:
            self.del_button.set_sensitive(False)
        else:
            self.del_button.set_sensitive(True)


    def on_port_entry_changed(self, port_entry):
        value = port_entry.get_text()

        # Allow an empty string or an integer
        try:
            int_value = int(value)
        except:
            port_entry.set_icon_from_stock(gtk.ENTRY_ICON_SECONDARY,\
                                           gtk.STOCK_DIALOG_ERROR)
            port_entry.set_icon_tooltip_text(gtk.ENTRY_ICON_SECONDARY,\
                                             'Requires an integer')
            self.apply_button.set_sensitive(False)
            return

        port_entry.set_icon_from_stock(gtk.ENTRY_ICON_SECONDARY, None)
        self.apply_button.set_sensitive(True)


    def on_tree_view_cell_edited(self, cell, path, new_text):
        iter = self.send_to_model.get_iter(path)
        self.send_to_model.set_value(iter, 0, new_text)


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