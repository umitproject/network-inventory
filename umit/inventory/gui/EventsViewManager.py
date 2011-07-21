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

from umit.inventory.common import NotificationTypes
from umit.inventory.gui.EventsViewWidget import EventsViewWidget
from umit.inventory.gui.SearchWindowManager import SearchWindowManager



class EventsViewManager(gobject.GObject):

    events_shown_options = {'Most Recent 25' : 25,\
                            'Most Recent 50' : 50,\
                            'Most Recent 75' : 75,\
                            'Most Recent 100' : 100}

    ALL_PROTOCOLS_SHOWN = 'All'


    def __init__(self, builder, ui_manager):
        gobject.GObject.__init__(self)
        self.events_model = None
        self.ui_manager = ui_manager

        # Get objects
        self.events_view = builder.get_object('events_view_top')
        self.events_widget_container =\
                builder.get_object('events_widget_container')
        self.find_events_button = builder.get_object('find_events_button')
        self.receive_events_button = builder.get_object('receive_events_button')
        self.filter_button = builder.get_object('filter_button')
        self.source_host_cbox = builder.get_object('source_host_cbox')
        self.events_shown_cbox = builder.get_object('events_shown_cbox')
        self.protocols_shown_cbox = builder.get_object('protocols_shown_cbox')
        self.all_cb = builder.get_object('all_checkbox')
        self.info_cb = builder.get_object('info_checkbox')
        self.recovery_cb = builder.get_object('recovery_checkbox')
        self.warning_cb = builder.get_object('warning_checkbox')
        self.security_cb = builder.get_object('security_checkbox')
        self.critical_cb = builder.get_object('critical_checkbox')
        self.unknown_cb = builder.get_object('unknown_checkbox')

        # For faster checking/unchecking
        self.cb_list = [self.info_cb, self.recovery_cb, self.warning_cb,\
                        self.security_cb, self.critical_cb, self.unknown_cb]
        self.cb_map = {NotificationTypes.info : self.info_cb,\
                       NotificationTypes.warning : self.warning_cb,\
                       NotificationTypes.recovery : self.recovery_cb,\
                       NotificationTypes.security : self.security_cb,\
                       NotificationTypes.critical : self.critical_cb,\
                       NotificationTypes.unknown : self.unknown_cb}

        # The widget where the events will be shown
        self.events_widget = EventsViewWidget(self.ui_manager,\
                self.tree_model_visible_func, self)
        self.events_widget_container.add(self.events_widget)
        self.events_widget.show()

        # Filter options
        self.events_shown = 0
        self.protocol_shown = self.ALL_PROTOCOLS_SHOWN
        self.hosts_shown = []
        self.types_shown = []

        self.init_events_shown()
        self.init_handlers()


    def init_events_shown(self):
        self.events_shown = 0
        self.events_shown_model = gtk.ListStore(gobject.TYPE_STRING)
        cell = gtk.CellRendererText()
        self.events_shown_cbox.pack_start(cell, True)
        self.events_shown_cbox.add_attribute(cell, 'text', 0)
        for option_key in self.events_shown_options.keys():

            iter = self.events_shown_model.append()
            self.events_shown_model.set(iter, 0, option_key)
            if self.events_shown is 0:
                self.events_shown = self.events_shown_options[option_key]
        self.events_shown_cbox.set_active(0)
        self.events_shown_cbox.set_model(self.events_shown_model)


    def add_notification(self, notification):
        self.events_widget.add_notification(notification)


    def set_protocols(self, protocols):
        self.protocols_model = gtk.ListStore(gobject.TYPE_STRING)
        cell = gtk.CellRendererText()
        self.protocols_shown_cbox.pack_start(cell, True)
        self.protocols_shown_cbox.add_attribute(cell, 'text', 0)
        iter = self.protocols_model.append()
        self.protocols_model.set(iter, 0, self.ALL_PROTOCOLS_SHOWN)
        for protocol in protocols:
            iter = self.protocols_model.append()
            self.protocols_model.set(iter, 0, protocol)
        self.protocols_shown_cbox.set_active(0)
        self.protocols_shown_cbox.set_model(self.protocols_model)


    def set_hosts(self, hosts):
        self.hosts_model = gtk.ListStore(gobject.TYPE_STRING)
        cell = gtk.CellRendererText()
        self.source_host_cbox.pack_start(cell, True)
        self.source_host_cbox.add_attribute(cell, 'text', 0)
        for host in hosts:
            iter = self.hosts_model.append()
            self.hosts_model.set(iter, 0, host)
        self.source_host_cbox.set_model(self.hosts_model)


    def set_ips(self, ips):
        pass


    @staticmethod
    def tree_model_visible_func(model, iter, user_data):
        events_view_manager = user_data

        # TODO host data
        notif_type = model.get_value(iter, EventsViewWidget.TREE_MODEL_COL_TYPE)
        protocol = model.get_value(iter, EventsViewWidget.TREE_MODEL_COL_PROT)

        # TODO look into this
        if notif_type is None or protocol is None:
            return False

        # Test the type
        if events_view_manager.types_shown is not []:
            if not events_view_manager.cb_map[notif_type].get_active():
                return False

        # TODO Test the host

        # Test the protocol
        if events_view_manager.protocol_shown != 'All':
            if not events_view_manager.protocol_shown != protocol:
                return False

        return True


    def init_handlers(self):
        self.find_events_button.connect('clicked',\
                self.on_find_events_button_clicked)
        self.receive_events_button.connect('toggled',\
                self.on_receive_events_button_toggled)
        self.filter_button.connect('clicked',\
                self.on_filter_button_clicked)
        self.all_cb.connect('toggled', self.on_all_cb_toggled)
        self.info_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.warning_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.recovery_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.critical_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.security_cb.connect('toggled', self.on_not_all_cb_toggled)
        self.unknown_cb.connect('toggled', self.on_not_all_cb_toggled)


    def checkbuttons_active(self):
        for cb in self.cb_list:
            if not cb.get_active():
                return False
        return True


    def on_find_events_button_clicked(self, find_events_button):
        self.ui_manager.search_events()


    def on_receive_events_button_toggled(self, receive_events_button):
        if receive_events_button.get_active():
            self.ui_manager.emit('subscribe', self.protocol_shown,\
                                 self.hosts_shown, self.types_shown)
        else:
            self.ui_manager.emit('unsubscribe')


    def on_filter_button_clicked(self, filter_button):
        # Get the filtered types
        self.types_shown = []
        if not self.all_cb.get_active():
            for notif_type in self.cb_map.keys():
                if self.cb_map[notif_type].get_active():
                    self.types_shown.append(notif_type)

        # Get the filtered hosts
        # TODO
        self.hosts_shown = []

        # Get the filtered protocol
        iter = self.protocols_shown_cbox.get_active_iter()
        self.protocol_shown = self.protocols_model.get_value(iter, 0)

        # Get the filtered events shown
        iter = self.events_shown_cbox.get_active_iter()
        events_shown_str = self.events_shown_model.get_value(iter, 0)
        self.events_shown = self.events_shown_options[events_shown_str]

        self.events_widget.refilter()

        self.ui_manager.emit('subscribe', self.protocol_shown,\
                             self.hosts_shown, self.types_shown)


    def on_all_cb_toggled(self, all_cb):
        active = all_cb.get_active()

        if active:
            for cb in self.cb_list:
                cb.set_active(True)
        elif self.checkbuttons_active():
            for cb in self.cb_list:
                cb.set_active(False)


    def on_not_all_cb_toggled(self, cb):
        active = cb.get_active()
        if not active:
            self.all_cb.set_active(False)
        elif self.checkbuttons_active():
            self.all_cb.set_active(True)
