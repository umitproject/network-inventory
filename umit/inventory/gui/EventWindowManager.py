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
import traceback
import time
from copy import copy

from umit.inventory.common import NotificationTypes


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

        self.description_text_view.set_wrap_mode(gtk.WRAP_WORD)


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
        self.event_window.set_modal(True)
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

