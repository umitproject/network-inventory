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


class HostsViewManager:

    MODEL_COL_HOSTINFO = 0
    MODEL_COL_HOSTNAME = 1

    def __init__(self, builder, ui_manager):
        self.ui_manager = ui_manager
        self.ni_notebook = ui_manager.ni_notebook
        self.hosts = None
        self.hostname = None
        self.ips = None
        self.initing_toggle_buttons_mode = False
        self.active_widget = None

        # Get the objects
        self.hosts_view = builder.get_object('hosts_view_top')
        self.hosts_tree_view = builder.get_object('hosts_tree_view')
        self.buttons_container = builder.get_object('buttons_container')
        self.widget_container = builder.get_object('widget_container')
        self.host_label = builder.get_object('host_label')

        # Check if the current page is focused
        current_page_index = self.ni_notebook.get_current_page()
        current_page = self.ni_notebook.get_nth_page(current_page_index)
        self.focused = current_page == self.hosts_view

        # Connect the handlers
        self.hosts_tree_view.connect('row-activated',\
                self.on_hosts_tree_view_row_activated)
        self.ui_manager.ni_notebook.connect('switch-page',\
                                            self.on_notebook_page_switch)
        
        # Init the hosts tree view
        self._init_hosts_tree_view()

        # Init the host views
        self.host_details_views = dict()
        self.active_host_detail_view = None
        self.toggle_buttons = list()
        self.host_selected = False


    def _init_hosts_tree_view(self):
        self.hosts_model = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.hosts_tree_view.set_model(self.hosts_model)

        cell = gtk.CellRendererText()
        col = gtk.TreeViewColumn('Hostname', cell)
        col.set_alignment(0.5)
        col.set_property('resizable', False)
        col.add_attribute(cell, 'text', self.MODEL_COL_HOSTINFO)
        self.hosts_tree_view.append_column(col)

        self.hosts_tree_view.set_enable_search(True)
        self.hosts_tree_view.set_search_column(0)


    def add_host_detail_view(self, detail_host_view):
        if not isinstance(detail_host_view, AbstractHostsView):
            return

        name = detail_host_view.get_name()
        self.host_details_views[name] = detail_host_view

        # Initialize the associated toggle button
        toggle_button = gtk.ToggleButton(name)
        toggle_button.set_property('width-request', 100)
        self.toggle_buttons.append(toggle_button)
        self.buttons_container.pack_start(toggle_button, False, False, 6)
        toggle_button.connect('toggled',\
                self.on_host_detail_view_button_toggled)
        toggle_button.show()

        # Activating the first added button
        if len(self.toggle_buttons) == 1:
            self.initing_toggle_buttons_mode = True
            toggle_button.set_active(True)
            self.active_host_detail_view = name


    def select_host(self, hostname):
        """
        Selects a host from the tree view and activates it's row.
        Returns True if hostname exists in the tree view's model.
        """
        # Locate the host
        first_iter = self.hosts_model.get_iter_root()
        if first_iter is None:
            return False

        iter = first_iter
        while iter is not None:
            current_hostname = self.hosts_model.get_value(iter,\
                    self.MODEL_COL_HOSTNAME)

            # Found the host
            if hostname == current_hostname:
                path = self.hosts_model.get_path(iter)
                col = self.hosts_tree_view.get_column(0)
                self.hosts_tree_view.row_activated(path, col)
                return True

            iter = self.hosts_model.iter_next(iter)

        return False


    def set_hosts(self, hosts):
        self.hosts = hosts
        if self.ips is not None:
            self._set_hosts_info()
            

    def set_ips(self, ips):
        self.ips = ips
        if self.hosts is not None:
            self._set_hosts_info()


    def _set_hosts_info(self):
        for i in range(0, len(self.hosts)):
            iter = self.hosts_model.append()
            hostinfo = str(self.hosts[i])
            if self.ips[i] is not '':
                hostinfo += ' (%s) ' % self.ips[i]
            self.hosts_model.set(iter,
                                 self.MODEL_COL_HOSTINFO, hostinfo,\
                                 self.MODEL_COL_HOSTNAME, str(self.hosts[i]))


    def on_notebook_page_switch(self, notebook, page, page_num):
        current_page = notebook.get_nth_page(page_num)
        if current_page != self.hosts_view and self.focused:
            self.focused = False
            if self.active_host_detail_view is not None:
                host_view = self.host_details_views[self.active_host_detail_view]
                host_view.set_host(None)
        if current_page == self.hosts_view:
            self.focused = True
            if self.active_host_detail_view is not None and\
               self.hostname is not None:
                host_view = self.host_details_views[self.active_host_detail_view]
                host_view.set_host(self.hostname)



    def on_hosts_tree_view_row_activated(self, treeview, path, view_column):
        model = treeview.get_model()
        iter = model.get_iter(path)

        hostname = model.get_value(iter, self.MODEL_COL_HOSTNAME)
        self.hostname = hostname
        host_view = self.host_details_views[self.active_host_detail_view]
        self.host_label.set_markup('<b>%s detail options:</b>' % hostname)

        # Clean the children (should be the initial label)
        children = self.widget_container.get_children()
        for child in children:
            self.widget_container.remove(child)

        host_view.set_host(hostname)

        # Add the new widget
        self.active_widget = host_view.get_widget()
        self.widget_container.add(self.active_widget)
        self.active_widget.show()
        self.host_selected = True


    def on_host_detail_view_button_toggled(self, view_button):
        if self.initing_toggle_buttons_mode:
            self.initing_toggle_buttons_mode = False
            return

        active = view_button.get_active()
        button_text = view_button.get_label()

        # We don't allow disabling the toggle button
        if not active and button_text == self.active_host_detail_view:
            view_button.set_active(True)
            return

        if active and button_text != self.active_host_detail_view:
            if self.active_host_detail_view is not None:
                host_view = self.host_details_views[self.active_host_detail_view]
                host_view.set_host(None)
    
            self.active_host_detail_view = button_text
            for toggle_button in self.toggle_buttons:
                if toggle_button == view_button:
                    continue
                toggle_button.set_active(False)

            if not self.host_selected:
                return

            if self.active_widget is not None:
                self.widget_container.remove(self.active_widget)
                self.active_widget.hide()
                self.active_widget.unparent()
            self.host_details_views[button_text].set_host(self.hostname)
            self.active_widget = self.host_details_views[button_text].get_widget()

            self.widget_container.add(self.active_widget)
            self.active_widget.show()



class AbstractHostsView:
    """
    Base class used to show a view for a host in the networks hosts tab.
    """

    def get_widget(self):
        """ Returns the actual widget which will be used to show host info. """
        pass


    def get_name(self):
        """
        Returns the name of the host view. This will be used for the toggle
        button label.
        """
        pass


    def set_host(self, hostname):
        """
        Called by the HostsManager when a host is selected and the view
        must set it's details according to the selected host. Called with
        None when the widget is focused out.
        """
        pass
