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
from copy import copy
import time

from umit.inventory.common import NotificationTypes



class EventsViewWidget(gtk.TreeView):

    # View Columns
    TREE_VIEW_COL_HOST = 0
    TREE_VIEW_COL_TYPE = 1
    TREE_VIEW_COL_TIME = 2
    TREE_VIEW_COL_PROT = 3
    TREE_VIEW_COL_DESC = 4

    # Model columns
    TREE_MODEL_COL_HOST = 0
    TREE_MODEL_COL_TYPE = 1
    TREE_MODEL_COL_TIME = 2
    TREE_MODEL_COL_PROT = 3
    TREE_MODEL_COL_DESC = 4
    TREE_MODEL_COL_NOTIF_OBJ = 5


    def __init__(self, ui_manager, filter_function=None,\
                 filter_func_user_data=None, activated_view_cols = None):
        self.ui_manager = ui_manager
        self.filter_function = filter_function
        self.filter_function_user_data = filter_func_user_data

        gtk.TreeView.__init__(self)

        if activated_view_cols is None:
            self.activated_view_cols = dict()
            self.activated_view_cols[self.TREE_VIEW_COL_DESC] = True
            self.activated_view_cols[self.TREE_VIEW_COL_PROT] = True
            self.activated_view_cols[self.TREE_VIEW_COL_TYPE] = True
            self.activated_view_cols[self.TREE_VIEW_COL_TIME] = True
            self.activated_view_cols[self.TREE_VIEW_COL_HOST] = True
        else:
            self.activated_view_cols = activated_view_cols
            
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
        if self.activated_view_cols[self.TREE_VIEW_COL_HOST]:
            cell = gtk.CellRendererText()
            col = gtk.TreeViewColumn('Source Host', cell)
            col.set_min_width(150)
            col.set_alignment(0.5)
            col.set_property('resizable', True)
            col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                                   self.TREE_MODEL_COL_HOST)
            self.append_column(col)

        # 2. Type Column
        if self.activated_view_cols[self.TREE_VIEW_COL_TYPE]:
            cell = gtk.CellRendererText()
            col = gtk.TreeViewColumn('Event Type', cell)
            col.set_min_width(100)
            col.set_alignment(0.5)
            col.set_property('resizable', True)
            col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                                   self.TREE_MODEL_COL_TYPE)
            self.append_column(col)

        # 3. Time Column
        if self.activated_view_cols[self.TREE_VIEW_COL_TIME]:
            cell = gtk.CellRendererText()
            col = gtk.TreeViewColumn('Time', cell)
            col.set_min_width(140)
            col.set_alignment(0.5)
            col.set_property('resizable', True)
            col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                                   self.TREE_MODEL_COL_TIME)
            self.append_column(col)

        # 4. Protocol Column
        if self.activated_view_cols[self.TREE_VIEW_COL_PROT]:
            cell = gtk.CellRendererText()
            col = gtk.TreeViewColumn('Protocol', cell)
            col.set_min_width(110)
            col.set_alignment(0.5)
            col.set_property('resizable', True)
            col.set_cell_data_func(cell, self.tree_view_col_data_func,\
                                   self.TREE_MODEL_COL_PROT)
            self.append_column(col)

        # 5. Short Description Column
        if self.activated_view_cols[self.TREE_VIEW_COL_DESC]:
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
        self.ui_manager.event_show_request(notification,\
                                           self.get_toplevel())


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


    def clear(self):
        self.model.clear()

