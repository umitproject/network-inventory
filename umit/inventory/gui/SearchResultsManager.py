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

from umit.inventory.gui.EventsViewWidget import EventsViewWidget


class SearchResultsManager:

    def __init__(self, ui_manager):
        self.ui_manager = ui_manager
        self.position = 0
        self.current_page_len = 0
        self.expected_position = 0
        self.search_id = 0
        self.count = 0
        self.page_size = 0


    def show_results(self, notifications_list, search_id=None,
                     count=0):
        try:
            self.current_page_len = len(notifications_list)
        except:
            self.current_page_len = 0
        self.count = count

        if search_id is not None:
            self._build_objects()
            self._initialize_objects()
            self.search_id = search_id
            self.position = 0
            if self.current_page_len < count:
                self.page_size = self.current_page_len

        self._populate_results(notifications_list)


    def _build_objects(self):
        builder = gtk.Builder()
        file_name =\
            self.ui_manager.get_glade_file_path('ni_search_results_window.glade')
        builder.add_from_file(file_name)
        self.results_window = builder.get_object('search_results_window')
        self.status_label = builder.get_object('status_label')
        self.next_button = builder.get_object('next_button')
        self.prev_button = builder.get_object('prev_button')
        self.close_button = builder.get_object('close_button')
        self.events_widget_container =\
                builder.get_object('events_widget_container')
        self.events_widget = EventsViewWidget(self.ui_manager)
        self.events_widget_container.add(self.events_widget)

        self.results_window.set_transient_for(self.ui_manager.main_window)
        self.results_window.set_modal(True)

        self.events_widget.show()
        self.results_window.show()


    def _initialize_objects(self):
        # Initialize Previous and Next buttons
        self.prev_button.set_sensitive(False)
        if self.count == self.current_page_len:
            self.next_button.set_sensitive(False)
        self.prev_button.connect('clicked', self.on_prev_button_clicked)
        self.next_button.connect('clicked', self.on_next_button_clicked)
        self.close_button.connect('clicked', self.on_close_button_clicked)
        self.results_window.connect('destroy', self.on_window_destroyed)


    def _populate_results(self, notifications_list):
        self.events_widget.clear()
        if self.current_page_len is 0:
            markup = '<b>No results found</b>'
            self.status_label.set_markup(markup)
            return

        markup = '<b> Showing results %d-%d out of %d</b>' % (self.position + 1,\
                self.position + self.current_page_len, self.count)
        self.status_label.set_markup(markup)

        for notification in notifications_list:
            self.events_widget.add_notification(notification)


    def search_next_callback(self, notifications_list=None,\
                             search_id=None, count=0, failed=False):
        if failed:
            msg = "The Notifications Server didn't respond to the request"
            self.ui_manager.show_run_state_error(msg, "Searching failed", False)
            self.results_window.destroy()
            return
        self.current_page_len = len(notifications_list)

        self.position = self.expected_position
        if self.expected_position is 0:
            self.prev_button.set_sensitive(False)
        else:
            self.prev_button.set_sensitive(True)

        self.position = self.expected_position
        if self.expected_position + self.current_page_len >= self.count:
            self.next_button.set_sensitive(False)
        else:
            self.next_button.set_sensitive(True)

        self._populate_results(notifications_list)


    def on_close_button_clicked(self, close_button):
        self.results_window.destroy()


    def on_window_destroyed(self, results_window):
        self.ui_manager.shell.stop_search(self.search_id)


    def on_prev_button_clicked(self, prev_button):
        prev_position =  max(0, self.position - self.page_size)
        self.ui_manager.shell.get_next_search_results(self.search_id,\
                prev_position, self.search_next_callback)
        self.expected_position = prev_position

        # Don't allow users to click on the next/prev buttons until the update
        self.next_button.set_sensitive(False)
        self.prev_button.set_sensitive(False)


    def on_next_button_clicked(self, next_button):
        self.ui_manager.shell.get_next_search_results(self.search_id,\
                self.position + self.current_page_len,\
                self.search_next_callback)
        self.expected_position = self.position + self.current_page_len

        # Don't allow users to click on the next/prev buttons until the update
        self.next_button.set_sensitive(False)
        self.prev_button.set_sensitive(False)

