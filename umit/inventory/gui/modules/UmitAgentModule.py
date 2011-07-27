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
from umit.inventory.gui.ServerCommunicator import Request


import os
import gtk
import gobject
import traceback
from copy import copy


#TODO refactoring paths
pixbuf_paths = os.path.join('umit', 'inventory', 'gui', 'pixmaps')
agent_logo = os.path.join(pixbuf_paths, 'agent_config.png')


class UmitAgentModule(Module):

    # Agent config model columns
    AGENT_CONFIG_MODEL_COL_NAME = 0
    AGENT_CONFIG_MODEL_COL_VALUE = 1
    

    def __init__(self, ui_manager, shell):
        Module.__init__(self, ui_manager, shell)

        self.configs = {}
        self.pending_configs = None

        self.config_window_manager = None

        # If the configurations are present and valid
        self.valid_configs = False


    def set_configs(self, configs):
        self.configs = configs
        self.pending_configs = None

        # Parse the configs
        try:
            agent_configs = configs['AgentListener']

            self.udp_port = str(agent_configs['listening_udp_port'])
            self.ssl_port = str(
                agent_configs['listening_ssl_port'])
            self.udp_auth = agent_configs['udp_authentication_enabled']
            self.ssl_auth = agent_configs['ssl_authentication_enabled']

            self.valid_configs = True
        except:
            traceback.print_exc()
            self.valid_configs = False


    def add_configs_ui(self, config_window_manager):
        self.config_window_manager = config_window_manager
        
        self.config_widget = None
        self._build_config_objects()
        self._init_host_combo()
        self._init_config_values()
        self._init_agent_config_treeview()
        self._init_config_handlers()

        pixbuf = gtk.gdk.pixbuf_new_from_file(agent_logo)
        config_window_manager.add_config_page(pixbuf,\
                'Umit Agents', self.config_widget)


    def _build_config_objects(self):
        file_name = self.ui_manager.glade_files['agent_config']
        builder = gtk.Builder()
        builder.add_from_file(file_name)
        self.config_widget = builder.get_object('agent_config_top')
        self.config_widget.unparent()
        self.config_notebook = builder.get_object('notebook')
        self.udp_port_entry = builder.get_object('udp_port_entry')
        self.udp_auth_cb = builder.get_object('udp_auth_cb')
        self.ssl_port_entry = builder.get_object('ssl_port_entry')
        self.ssl_auth_cb = builder.get_object('ssl_auth_cb')
        self.host_combo = builder.get_object('host_combo')
        self.config_treeview = builder.get_object('config_treeview')
        self.select_button = builder.get_object('select_button')
        self.agent_restore_button = builder.get_object('agent_restore_button')
        self.agent_apply_button = builder.get_object('agent_apply_button')
        self.module_restore_button = builder.get_object('module_restore_button')
        self.module_apply_button = builder.get_object('module_apply_button')

        self.config_notebook.remove_page(-1)
        self.select_button.set_sensitive(False)
        self.agent_apply_button.set_sensitive(False)
        self.agent_restore_button.set_sensitive(False)

        self.config_model = None
        

    def _init_host_combo(self):
        self.host_combo.set_active(-1)

        hostnames = self.shell.get_host_names()

        self.host_model = gtk.ListStore(gobject.TYPE_STRING)
        for hostname in hostnames:
            iter = self.host_model.append()
            self.host_model.set(iter, 0, hostname)
        
        self.host_combo.set_model(self.host_model)
        hostname_combo_entry = self.host_combo.get_child()
        hostname_combo_entry.set_text('')
        hostname_entry_completion = gtk.EntryCompletion()
        hostname_entry_completion.set_model(self.host_model)
        hostname_entry_completion.set_text_column(0)
        hostname_entry_completion.set_inline_completion(True)
        hostname_combo_entry.set_completion(hostname_entry_completion)


    def _init_config_values(self):
        self.udp_port_entry.set_text(self.udp_port)
        self.ssl_port_entry.set_text(self.ssl_port)
        self.udp_auth_cb.set_active(bool(self.udp_auth))
        self.ssl_auth_cb.set_active(bool(self.ssl_auth))

        self.port_entries_valid = {self.udp_port_entry : True,\
                                   self.ssl_port_entry : True}


    def _init_agent_config_treeview(self):
        # Option name column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Option Name', cell)
        col.set_min_width(150)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_option_name_data_func)
        self.config_treeview.append_column(col)

        # Option value column
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Option Value', cell)
        col.set_min_width(150)
        col.set_alignment(0.5)
        col.set_property('resizable', True)
        col.set_cell_data_func(cell, self.tree_view_option_value_data_func)
        self.config_treeview.append_column(col)

        cell.connect('edited', self.on_agent_config_value_cell_edited)


    def tree_view_option_name_data_func(self, column, cell, model,\
                                        iter, user_data):
        # Get option or section name
        name = model.get_value(iter, self.AGENT_CONFIG_MODEL_COL_NAME)

        cell.set_property('markup', '<b>%s</b>' % name)


    def tree_view_option_value_data_func(self, column, cell, model,\
                                         iter, user_data):
        # Determine if it's a section or option iter
        is_section_iter = model.iter_parent(iter) is None
        
        # Get option value
        value = model.get_value(iter, self.AGENT_CONFIG_MODEL_COL_VALUE)

        # Editable only if it's an option iter
        cell.set_property('editable', not is_section_iter)
        cell.set_property('text', value)

    
    def on_agent_config_value_cell_edited(self, cellrenderertext, path,\
                                          new_text):
        pass


    def _init_config_handlers(self):
        self.module_apply_button.connect('clicked',\
                self.on_module_apply_button_clicked)
        self.module_restore_button.connect('clicked',\
                self.on_module_restore_button_clicked)
        self.agent_apply_button.connect('clicked',\
                self.on_agent_apply_button_clicked)
        self.agent_restore_button.connect('clicked',\
                self.on_agent_restore_button_clicked)
        self.select_button.connect('clicked', self.on_select_button_clicked)
        self.udp_port_entry.connect('changed', self.on_port_entry_changed)
        self.ssl_port_entry.connect('changed', self.on_port_entry_changed)
        self.host_combo.connect('changed', self.on_host_combo_changed)


    def on_module_apply_button_clicked(self, module_apply_button):
        # Get the values
        self.udp_port = int(self.udp_port_entry.get_text())
        self.ssl_port = int(self.ssl_port_entry.get_text())
        self.udp_auth = self.udp_auth_cb.get_active()
        self.ssl_auth = self.ssl_auth_cb.get_active()

        # Parse the configs into a dictionary
        configs = dict()
        agent_configs = dict()
        agent_configs['listening_udp_port'] = self.udp_port
        agent_configs['listening_ssl_port'] = self.ssl_port
        agent_configs['udp_authentication_enabled'] = self.udp_auth
        agent_configs['ssl_authentication_enabled'] = self.ssl_auth
        configs['AgentListener'] = agent_configs
        self.pending_configs = configs

        # Send the configs to the server
        self.shell.send_request(SetConfigsRequest(self.shell.get_username(),\
                self.shell.get_password(), configs, self.send_configs_callback))


    def send_configs_callback(self, failed):
        if not failed:
            self.set_configs(copy(self.pending_configs))
        else:
            self.set_configs(copy(self.configs))


    def on_module_restore_button_clicked(self, module_restore_button):
        self._init_config_values()


    def on_host_combo_changed(self, host_combo):
        hostname_combo_entry = host_combo.get_child()
        hostname = hostname_combo_entry.get_text()

        if hostname not in ['', None]:
            self.select_button.set_sensitive(True)
        else:
            self.select_button.set_sensitive(False)


    def on_port_entry_changed(self, entry):
        value = entry.get_text()

        # Allow an empty string or an integer
        try:
            int_value = int(value)
        except:
            entry.set_icon_from_stock(gtk.ENTRY_ICON_SECONDARY,\
                                      gtk.STOCK_DIALOG_ERROR)
            entry.set_icon_tooltip_text(gtk.ENTRY_ICON_SECONDARY,\
                                        'Requires an integer')
            self.port_entries_valid[entry] = False
            self.module_apply_button.set_sensitive(False)
            return

        self.port_entries_valid[entry] = True
        entry.set_icon_from_stock(gtk.ENTRY_ICON_SECONDARY, None)

        for valid_entry_value in self.port_entries_valid.values():
            if not valid_entry_value:
                return
        self.module_apply_button.set_sensitive(True)


    def on_select_button_clicked(self, select_button):
        # Send the get configs request to the server
        username = self.shell.get_username()
        password = self.shell.get_password()

        hostname_combo_entry = self.host_combo.get_child()
        hostname = hostname_combo_entry.get_text()

        request = AgentGetConfigsRequest(username, password, hostname, self)
        self.shell.send_request(request)

        self.config_treeview.set_model(None)

        select_button.set_sensitive(False)
        

    def on_agent_apply_button_clicked(self, agent_apply_button):
        pass


    def on_agent_restore_button_clicked(self, agent_restore_button):
        pass


    def agent_configs_error(self, hostname):
        """Called when there was an error receiving the configs from the agent"""
        if self.config_window_manager is None:
            return

        error_title = 'Failed To Connect'
        error_msg = 'Failed to connect to %s or an internal server' % hostname
        error_msg += ' error occured'
        self.config_window_manager.show_error(error_msg, error_title)

        self.select_button.set_sensitive(True)
    

    def agent_configs_received(self, configs):
        """Called when the agent configs were received"""
        # Initialize the model
        self.config_model = gtk.TreeStore(gobject.TYPE_STRING,\
                                          gobject.TYPE_STRING)

        try:
            for section_name in configs.keys():
                iter = self.config_model.append(None)
                self.config_model.set(iter,\
                    self.AGENT_CONFIG_MODEL_COL_NAME, section_name,\
                    self.AGENT_CONFIG_MODEL_COL_VALUE, '')

                for option_name in configs[section_name].keys():
                    option_value = configs[section_name][option_name]

                    iter2 = self.config_model.append(iter)
                    self.config_model.set(iter2,\
                        self.AGENT_CONFIG_MODEL_COL_NAME, option_name,\
                        self.AGENT_CONFIG_MODEL_COL_VALUE, option_value)

            self.config_treeview.set_model(self.config_model)
            self.config_treeview.expand_all()
        except:
            error_title = 'Invalid response'
            error_msg = 'Received an invalid response from the host.\n'
            error_msg += 'It\'s installation may be corrupt.'
            self.config_window_manager.show_error(error_msg, error_title)

        self.select_button.set_sensitive(True)
        

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



class AgentGetConfigsRequest(Request):

    def __init__(self, username, password, hostname, agent_module):
        self.agent_module = agent_module
        self.hostname = hostname

        agent_request_body = dict()
        agent_request_body['hostname'] = hostname

        agent_request = dict()
        agent_request['agent_request_type'] = 'GET_CONFIGS'
        agent_request['agent_request_body'] = agent_request_body

        Request.__init__(self, username, password, agent_request,\
                            'AgentListener')


    def handle_response(self, response):
        try:
            response_code = response['response_code']
            if response_code != 200:
                gobject.idle_add(self.agent_module.agent_configs_error,\
                                 self.hostname)
                return
            
            response_body = response['body']
            configs = response_body['configs']
        except:
            traceback.print_exc()
            gobject.idle_add(self.agent_module.agent_configs_error,\
                             self.hostname)
            return

        gobject.idle_add(self.agent_module.agent_configs_received, configs)
