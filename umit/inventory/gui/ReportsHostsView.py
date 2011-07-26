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
import time
import datetime

from umit.inventory.gui.TimePickerManager import TimePickerManager
from umit.inventory.gui.HostsViewManager import AbstractHostsView


class ReportsHostsView(AbstractHostsView):

    MODEL_COL_TIME = 0
    MODEL_COL_DESCRIPTION = 1
    
    def __init__(self, ui_manager):
        self.ui_manager = ui_manager
        self.model = None
        self.hostname = None
        self.search_id = None
        self.start_time = None
        self.end_time = None

        self.time_picker_manager = TimePickerManager(self.ui_manager,\
                ['start_time', 'end_time'], ui_manager.main_window)

        # Get the objects
        builder = gtk.Builder()
        file_name = self.ui_manager.glade_files['reports_hosts']
        builder.add_from_file(file_name)
        self.reports_view = builder.get_object('reports_hosts_view_top')
        self.reports_view.unparent()
        self.prev_button = builder.get_object('prev_button')
        self.prev_button.set_sensitive(False)
        self.next_button = builder.get_object('next_button')
        self.next_button.set_sensitive(False)
        self.start_time_button = builder.get_object('start_time_button')
        self.end_time_button = builder.get_object('end_time_button')
        self.filter_button = builder.get_object('filter_button')
        self.reports_tree_view = builder.get_object('reports_tree_view')
        self.report_text_view = builder.get_object('report_text_view')

        self._init_reports_tree_view()
        self._init_handlers()


    def _init_reports_tree_view(self):
        self.model = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.reports_tree_view.set_model(self.model)

        # Add the column (only one column: the time the report was generated)
        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Report Time', cell)
        col.set_min_width(200)
        col.set_alignment(0.5)
        col.set_property('resizable', False)
        col.add_attribute(cell, 'text', self.MODEL_COL_TIME)
        self.reports_tree_view.append_column(col)
        self.reports_tree_view.set_headers_visible(False)


    def _init_handlers(self):
        self.prev_button.connect('clicked', self.on_prev_button_clicked)
        self.next_button.connect('clicked', self.on_next_button_clicked)
        self.filter_button.connect('clicked', self.on_filter_button_clicked)
        self.reports_tree_view.connect('row-activated',\
                self.on_reports_tree_view_row_activated)
        self.start_time_button.connect('clicked',\
                self.on_time_button_clicked, 'start_time')
        self.end_time_button.connect('clicked',\
                self.on_time_button_clicked, 'end_time')
        self.time_picker_manager.connect('value-changed', self.on_time_changed)


    def _populate_results(self, notifications_list):
        self.model.clear()

        # Clear the description text view
        buffer = self.report_text_view.get_buffer()
        buffer.set_text('')
        
        for notification in notifications_list:
            timestamp = notification['timestamp']
            description = notification['description']
            iter = self.model.append()
            self.model.set(iter,\
                           self.MODEL_COL_TIME, time.ctime(timestamp),\
                           self.MODEL_COL_DESCRIPTION, description)


    def reports_tree_view_col_data_func(self, column, cell, model, iter, model_col):
        col_value = model.get_value(iter, model_col)
        cell.set_property('text', time.ctime(col_value))


    def on_time_button_clicked(self, time_button, target):
        self.time_picker_manager.choose_value(target)


    def on_time_changed(self, time_manager, target, target_value):
        if target_value == -1.0:
            button_text = 'Choose Time ...'
        else:
            date_time = datetime.datetime.fromtimestamp(target_value)
            button_text = date_time.strftime('%B %d %Y %H:%M:%S')

        target_button = None
        if target == 'start_time':
            target_button = self.start_time_button
            self.start_time = target_value if target_value != -1.0 else None
        elif target == 'end_time':
            target_button = self.end_time_button
            self.end_time = target_value if target_value != -1.0 else None

        if target_button is None:
            return

        target_button.set_label(button_text)


    def on_reports_tree_view_row_activated(self, treeview, path, view_column):
        model = treeview.get_model()
        iter = model.get_iter(path)

        description = model.get_value(iter, self.MODEL_COL_DESCRIPTION)
        buffer = self.report_text_view.get_buffer()
        buffer.set_text(description)


    def on_prev_button_clicked(self, prev_button):
        self.expected_position = self.position - self.current_page_len
        self.ui_manager.shell.get_next_search_results(self.search_id,\
                self.expected_position, self.search_next_callback_function)
        self.prev_button.set_sensitive(False)
        self.next_button.set_sensitive(False)


    def on_next_button_clicked(self, next_button):
        self.expected_position = self.position + self.current_page_len
        self.ui_manager.shell.get_next_search_results(self.search_id,\
                self.expected_position, self.search_next_callback_function)
        self.prev_button.set_sensitive(False)
        self.next_button.set_sensitive(False)


    def on_filter_button_clicked(self, filter_button):
        self.set_host(self.hostname)


    def get_name(self):
        return 'Reports'


    def get_widget(self):
        return self.reports_view


    def set_host(self, hostname):
        # Query the Server database for reports for this host
        self.hostname = hostname
        self.model.clear()

        # Clear the description text view
        buffer = self.report_text_view.get_buffer()
        buffer.set_text('')

        # If we have an active search, stop it
        if self.search_id is not None:
            self.ui_manager.shell.stop_search(self.search_id)
            self.search_id = None

        # If we shouldn't show any data
        if hostname is None:
            return

        # Only interested in the description and timestamp fields
        fields = ['description', 'timestamp']

        # Sorting descending by timestamp
        sort = [('timestamp', False)]

        # Conditions to show the events
        spec = dict()
        spec['hostname'] = {'$in' : [hostname.strip()]}
        spec['is_report'] = {'$ne' : False}

        if self.start_time or self.end_time:
            spec['timestamp'] = dict()
        if self.start_time:
            spec['timestamp']['$gt'] = self.start_time
        if self.end_time:
            spec['timestamp']['$lt'] = self.end_time

        self.ui_manager.shell.search_notifications(spec, sort, fields,\
                self.search_callback_function)


    def search_callback_function(self, notifications_list=None,\
            search_id=None, count=0, position=0, failed=False):
        if failed:
            self.ui_manager.show_run_state_error("", "Report fetching failed")
            return
        self.search_id = search_id
        self.current_page_len = len(notifications_list)
        self.count = count
        self.position = 0

        # If we don't have any more reports
        if self.current_page_len < count:
            self.next_button.set_sensitive(True)
        else:
            self.next_button.set_sensitive(False)

        self._populate_results(notifications_list)


    def search_next_callback_function(self, notifications_list=None,\
            search_id=None, count=0, position=0, failed=False):
        if failed:
            self.ui_manager.show_run_state_error("", "Report fetching failed")
            return

        self.current_report_len = len(notifications_list)
        self.position = self.expected_position
        if self.position + self.current_report_len < self.count:
            self.next_button.set_sensitive(True)
        else:
            self.next_button.set_sensitive(False)
        if self.position > 0:
            self.prev_button.set_sensitive(True)
        else:
            self.prev_button.set_sensitive(False)

        self._populate_results(notifications_list)
        