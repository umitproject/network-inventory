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
import datetime

from umit.inventory.gui.SearchResultsManager import SearchResultsManager
from umit.inventory.gui.TimePickerManager import TimePickerManager
from umit.inventory.common import NotificationTypes


class SearchWindowManager:

    def __init__(self, ui_manager):
        self.ui_manager = ui_manager
        self.search_results_manager = SearchResultsManager(ui_manager)

        self.window_shown = False
        self.protocols = None
        self.hosts = None
        self.ips = None
        self.protocols_model = None
        self.hosts_model = None
        self.ips_model = None


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
        file_name = self.ui_manager.get_glade_file_path('ni_search_window.glade')
        self.search_window = builder.add_from_file(file_name)
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
        self.find_button = builder.get_object('find_button')
        self.close_button = builder.get_object('close_button')

        self.time_picker_manager = TimePickerManager(self.ui_manager,\
                ['start_time', 'end_time'], self.search_window)

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
        self.find_button.connect('clicked', self.on_find_button_clicked)
        self.close_button.connect('clicked', self.on_close_button_clicked)
        self.time_picker_manager.connect('value-changed', self.on_time_changed)


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


    def on_find_button_clicked(self, find_button):
        # Showing all fields
        fields = None

        # Sorting descending by timestamp
        sort = [('timestamp', False)]

        # Conditions to show the events
        spec = dict()
        if self.hostname:
            spec['hostname'] = {'$in' : [self.hostname.strip()]}
        if self.ip_addr:
            spec['source_host_ipv4'] = {'$in': [self.ip_addr.strip()]}
        if self.protocol:
            spec['protocol'] = {'$in' : [self.protocol.strip()]}
        spec['event_type'] = {'$in' : self.shown_events_types}

        if self.start_time or self.end_time:
            spec['timestamp'] = dict()
        if self.start_time:
            spec['timestamp']['$gt'] = self.start_time
        if self.end_time:
            spec['timestamp']['$lt'] = self.end_time

        # Not searching reports
        spec['is_report'] = {'$ne' : True}

        self.ui_manager.shell.search_notifications(spec, sort, fields,\
                self.search_callback_function)


    def on_close_button_clicked(self, close_button):
        self.search_window.destroy()


    def on_window_destroyed(self, window):
        self.window_shown = False
        self.time_picker_manager.close()


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


    def on_time_button_clicked(self, time_button, target):
        self.time_picker_manager.choose_value(target)


    def on_time_changed(self, time_manager, target_name, target_value):
        if target_value == -1.0:
            button_text = 'Choose Time ...'
        else:
            date_time = datetime.datetime.fromtimestamp(target_value)
            button_text = date_time.strftime('%B %d %Y %H:%M:%S')

        target_button = None
        if target_name == 'start_time':
            target_button = self.start_time_button
            self.start_time = target_value if target_value != -1.0 else None
        elif target_name == 'end_time':
            target_button = self.end_time_button
            self.end_time = target_value if target_value != -1.0 else None

        if target_button is None:
            return

        target_button.set_label(button_text)


    def on_type_cb_toggled(self, type_cb):
        active = type_cb.get_active()
        type_value = self.type_map[type_cb]
        if active and type_value not in self.shown_events_types:
            self.shown_events_types.append(type_value)
        if not active and type_value in self.shown_events_types:
            self.shown_events_types.remove(type_value)


    def search_callback_function(self, notifications_list=None,\
            search_id=None, count=0, position=0, failed=False):
        if failed:
            self.ui_manager.show_run_state_error("", "Searching failed")
            self.search_window.destroy()
            return
        self.search_window.destroy()
        self.search_window = None
        self.search_results_manager.show_results(notifications_list,\
                search_id, count)
