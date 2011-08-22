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

import gtk
import gobject


class HostSelectManager:

    def __init__(self, ui_manager):
        self.ui_manager = ui_manager

        
    def _build_objects(self):
        glade_file_name =\
            self.ui_manager.get_glade_file_path('ni_host_select.glade')
        builder = gtk.Builder()
        builder.add_from_file(glade_file_name)

        self.host_select_window = builder.get_object('host_select_window')
        self.hostname_combo = builder.get_object('hostname_combo')
        self.select_button = builder.get_object('select_button')
        self.close_button = builder.get_object('close_button')

        self._init_hostname_combo()


    def _init_hostname_combo(self):
        self.hostname_model = gtk.ListStore(gobject.TYPE_STRING)

        # Add the hosts to the list store
        for host in self.hosts:
            iter = self.hostname_model.append()
            self.hostname_model.set(iter, 0, host)
        
        self.hostname_combo.set_model(self.hostname_model)
        hostname_combo_entry = self.hostname_combo.get_child()
        hostname_entry_completion = gtk.EntryCompletion()
        hostname_entry_completion.set_model(self.hostname_model)
        hostname_entry_completion.set_text_column(0)
        hostname_entry_completion.set_inline_completion(True)
        hostname_combo_entry.set_completion(hostname_entry_completion)


    def _init_handlers(self):
        self.close_button.connect('clicked', self.on_close_button_clicked)
        self.select_button.connect('clicked', self.on_select_button_clicked)


    def on_close_button_clicked(self, close_button):
        self.host_select_window.destroy()


    def on_select_button_clicked(self, select_button):
        hostname_entry = self.hostname_combo.get_child()
        hostname = hostname_entry.get_text()
    
        if hostname not in [None, '']:
            host_matched =\
                    self.ui_manager.hosts_view_manager.select_host(hostname)

        self.host_select_window.destroy()

        if not host_matched:
            err_msg = 'Hostname %s not found in your network' % hostname
            title = 'Host Not Found'
            self.ui_manager.show_run_state_error(err_msg, title)
        else:
            # Activate the hosts page
            self.ui_manager.ni_notebook.set_current_page(1)


    def show(self, parent_window, hosts):
        self.parent_window = parent_window
        self.hosts = hosts
    
        self._build_objects()
        self._init_handlers()

        self.host_select_window.set_transient_for(parent_window)
        self.host_select_window.set_modal(True)
        self.host_select_window.show()