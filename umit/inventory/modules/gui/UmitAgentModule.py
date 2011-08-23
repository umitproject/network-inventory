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

        self.agent_configs = None
        

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
        self._init_users_tree_view()
        self._init_config_handlers()

        self.shell.send_request(AgentGetUsersRequest(
            self.shell.username, self.shell.password, self))

        agent_logo = self.ui_manager.get_pixmap_file_path('agent_config.png')
        pixbuf = gtk.gdk.pixbuf_new_from_file(agent_logo)
        config_window_manager.add_config_page(pixbuf,
                'Umit Agents', self.config_widget)


    def _build_config_objects(self):
        file_name = self.ui_manager.get_glade_file_path('ni_agents_config.glade')
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
        self.users_tree_view = builder.get_object('users_tree_view')
        self.add_user_button = builder.get_object('add_user_button')
        self.del_user_button = builder.get_object('del_user_button')
        self.del_user_button.set_sensitive(False)
        self.add_user_button.set_sensitive(False)
        
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


    def _init_users_tree_view(self):
        self.tree_view_cell = gtk.CellRendererText()
        self.tree_view_col = gtk.TreeViewColumn('Username', self.tree_view_cell)
        self.tree_view_col.set_property('resizable', False)
        self.tree_view_col.add_attribute(self.tree_view_cell, 'text', 0)
        self.users_tree_view.append_column(self.tree_view_col)

        # Init to addresses tree view
        self.users_tree_model = gtk.ListStore(gobject.TYPE_STRING)
        self.users_tree_view.set_headers_visible(False)
        self.users_tree_view.set_model(self.users_tree_model)

        self.users_tree_view_selection = self.users_tree_view.get_selection()


    def tree_view_option_name_data_func(self, column, cell, model, iter):
        # Get option or section name
        name = model.get_value(iter, self.AGENT_CONFIG_MODEL_COL_NAME)

        cell.set_property('markup', '<b>%s</b>' % name)


    def tree_view_option_value_data_func(self, column, cell, model, iter):
        # Determine if it's a section or option iter
        is_section_iter = model.iter_parent(iter) is None
        
        # Get option value
        value = model.get_value(iter, self.AGENT_CONFIG_MODEL_COL_VALUE)

        # Editable only if it's an option iter
        cell.set_property('editable', not is_section_iter)
        cell.set_property('text', value)

    
    def on_agent_config_value_cell_edited(self, cellrenderertext, path,\
                                          new_text):
        iter = self.config_model.get_iter(path)
        self.config_model.set(iter, self.AGENT_CONFIG_MODEL_COL_VALUE, new_text)


    def on_config_treeview_row_activated(self, treeview, path, view_column):
        if treeview.row_expanded(path):
            treeview.collapse_row(path)
        else:
            treeview.expand_row(path, False)


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
        self.config_treeview.connect('row-activated',\
                self.on_config_treeview_row_activated)
        self.add_user_button.connect('clicked', self.on_add_user_button_clicked)
        self.del_user_button.connect('clicked', self.on_del_user_button_clicked)
        self.users_tree_view_selection.connect('changed',
                self.on_users_tree_view_selection_changed)


    def on_users_tree_view_selection_changed(self, selection):
        model, selected_rows = selection.get_selected_rows()

        if len(selected_rows) is 0:
            self.del_user_button.set_sensitive(False)
        else:
            self.del_user_button.set_sensitive(True)


    def on_add_user_button_clicked(self, button):
        add_user_dialog = AddUserDialog(self.shell, self.ui_manager,
                self.users_tree_model, self.config_window_manager.config_window)
        add_user_dialog.show()


    def on_del_user_button_clicked(self, button):
        model, selected_paths =\
                self.users_tree_view_selection.get_selected_rows()

        selected_rows = list()
        for selected_path in selected_paths:
            selected_rows.append(gtk.TreeRowReference(model, selected_path))

        for selected_row in selected_rows:
            path = selected_row.get_path()
            iter = model.get_iter(path)
            username = model.get_value(iter, 0)
            request = AgentDelUserRequest(self.shell.username, self.shell.password,
                                          username)
            self.shell.send_request(request)
            model.remove(iter)


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
        self.agent_configs = None
        select_button.set_sensitive(False)
        self.agent_apply_button.set_sensitive(False)
        self.agent_restore_button.set_sensitive(False)
        

    def on_agent_apply_button_clicked(self, agent_apply_button):
        # Get the configs
        configs = dict()
        try:
            iter = self.config_model.get_iter_first()
            while iter is not None:
                section_name = self.config_model.get_value(iter,\
                    self.AGENT_CONFIG_MODEL_COL_NAME)
                configs[section_name] = dict()
                
                iter2 = self.config_model.iter_children(iter)
                while iter2 is not None:
                    option_name = self.config_model.get_value(iter2,\
                        self.AGENT_CONFIG_MODEL_COL_NAME)
                    option_value = self.config_model.get_value(iter2,\
                        self.AGENT_CONFIG_MODEL_COL_VALUE)
                    configs[section_name][option_name] = option_value
                    
                    iter2 = self.config_model.iter_next(iter2)
                iter = self.config_model.iter_next(iter)
        except:
            traceback.print_exc()
            return

        username = self.shell.get_username()
        password = self.shell.get_password()

        hostname_combo_entry = self.host_combo.get_child()
        hostname = hostname_combo_entry.get_text()

        request = AgentSetConfigsRequest(username, password, hostname,\
                                         configs, self)
        self.shell.send_request(request)

        self.agent_configs = configs
        

    def on_agent_restore_button_clicked(self, agent_restore_button):
        self.agent_configs_received(self.agent_configs)


    def agent_configs_error(self, hostname):
        """Called when there was an error receiving the configs from the agent"""
        if self.config_window_manager is None:
            return

        error_title = 'Failed To Connect'
        error_msg = 'Failed to connect to %s or an internal server' % hostname
        error_msg += ' error occured'
        self.config_window_manager.show_error(error_msg, error_title)

        self.select_button.set_sensitive(True)
        self.agent_apply_button.set_sensitive(False)
        self.agent_restore_button.set_sensitive(False)
       

    def agent_configs_received(self, configs):
        """Called when the agent configs were received"""
        if configs is None:
            return
        
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
            self.agent_configs = configs
            self.agent_apply_button.set_sensitive(True)
            self.agent_restore_button.set_sensitive(True)
        except:
            error_title = 'Invalid response'
            error_msg = 'Received an invalid response from the host.\n'
            error_msg += 'It\'s installation may be corrupt.'
            self.agent_apply_button.set_sensitive(False)
            self.agent_restore_button.set_sensitive(False)
            self.config_window_manager.show_error(error_msg, error_title)

        self.select_button.set_sensitive(True)


    def agent_get_users_error(self):
        # TODO - maybe show an error
        pass


    def agent_get_users_success(self, usernames):
        try:
            for username in usernames:
                iter = self.users_tree_model.append()
                self.users_tree_model.set(iter, 0, username)
            self.add_user_button.set_sensitive(True)
        except:
            # TODO - maybe show an error
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



class AddUserDialog:

    def __init__(self, shell, ui_manager, users_tree_model, parent_window):
        self.shell = shell
        self.ui_manager = ui_manager
        self.users_tree_model = users_tree_model
        self.parent_window = parent_window


    def show(self):
        file_name = self.ui_manager.get_glade_file_path('ni_add_agent_user_window.glade')
        builder = gtk.Builder()
        builder.add_from_file(file_name)
        self.window = builder.get_object('ni_add_agent_user_window')
        self.add_user_button = builder.get_object('add_user_button')
        self.cancel_button = builder.get_object('cancel_button')
        self.username_entry = builder.get_object('username_entry')
        self.password_entry = builder.get_object('password_entry')

        # Connect the handlers
        self.add_user_button.connect('clicked', self.on_add_user_button_clicked)
        self.cancel_button.connect('clicked', self.on_cancel_button_clicked)

        self.window.set_transient_for(self.parent_window)
        icon = self.parent_window.get_icon()
        self.window.set_icon(icon)
        self.window.set_modal(True)
        self.window.show()


    def on_add_user_button_clicked(self, button):
        # Test the user isn't already in the model
        iter = self.users_tree_model.get_iter_first()
        while iter is not None:
            username = self.users_tree_model.get_value(iter, 0)
            if username == self.username_entry.get_text():
                self.window.destroy()
                return
            iter = self.users_tree_model.iter_next(iter)

        iter = self.users_tree_model.append()
        self.users_tree_model.set(iter, 0, self.username_entry.get_text())

        request = AgentAddUserRequest(self.shell.username, self.shell.password,
                self.username_entry.get_text(), self.password_entry.get_text())
        self.shell.send_request(request)
        
        self.window.destroy()


    def on_cancel_button_clicked(self, button):
        self.window.destroy()
    


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



class AgentSetConfigsRequest(Request):

    def __init__(self, username, password, hostname, configs, agent_module):
        self.agent_module = agent_module
        self.hostname = hostname
        self.configs = configs

        agent_request_body = dict()
        agent_request_body['hostname'] = hostname
        agent_request_body['configs'] = configs
        
        agent_request = dict()
        agent_request['agent_request_type'] = 'SET_CONFIGS'
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
        except:
            traceback.print_exc()
            gobject.idle_add(self.agent_module.agent_configs_error,\
                             self.hostname)
            return



class AgentAddUserRequest(Request):

    def __init__(self, username, password, added_username, added_password):

        agent_request_body = dict()
        agent_request_body['agent_username'] = added_username
        agent_request_body['agent_password'] = added_password

        agent_request = dict()
        agent_request['agent_request_type'] = 'ADD_USER'
        agent_request['agent_request_body'] = agent_request_body

        Request.__init__(self, username, password, agent_request,\
                            'AgentListener')



class AgentDelUserRequest(Request):

    def __init__(self, username, password, deleted_username):

        agent_request_body = dict()
        agent_request_body['agent_username'] = deleted_username

        agent_request = dict()
        agent_request['agent_request_type'] = 'DEL_USER'
        agent_request['agent_request_body'] = agent_request_body

        Request.__init__(self, username, password, agent_request,\
                            'AgentListener')



class AgentGetUsersRequest(Request):

    def __init__(self, username, password, agent_module):
        self.agent_module = agent_module

        agent_request = dict()
        agent_request['agent_request_type'] = 'GET_USERS'
        agent_request['agent_request_body'] = dict()

        Request.__init__(self, username, password, agent_request,\
                            'AgentListener')


    def handle_response(self, response):
        try:
            response_code = response['response_code']
            if response_code != 200:
                gobject.idle_add(self.agent_module.agent_get_users_error)
                return

            response_body = response['body']
            usernames = response_body['usernames']
        except:
            traceback.print_exc()
            gobject.idle_add(self.agent_module.agent_get_users_error)
            return

        gobject.idle_add(self.agent_module.agent_get_users_success, usernames)