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
import time


class TimePickerManager(gobject.GObject):
    __gsignals__ = {
        # Emitted when a target value is changed
        # Parameters: target name, target value
        "value-changed": (gobject.SIGNAL_RUN_FIRST,
                          gobject.TYPE_NONE,
                          (str, float)),
        }

    def __init__(self, ui_manager, targets, parent_window):
        gobject.GObject.__init__(self)
        self.ui_manager = ui_manager
        
        # Mapping target names to their values
        self.targets_dict = dict()
        for target in targets:
            self.targets_dict[target] = None

        self.parent_window = parent_window

        # The actual time picker widget
        self.time_popup = None


    def close(self):
        if self.time_popup is not None:
            self.time_popup.destroy()


    def choose_value(self, target):
        """ Called when we should show the time picker widget """
        if target not in self.targets_dict.keys():
            return

        if self.time_popup is not None:
            self.time_popup.destroy()

        # Build the objects
        builder = gtk.Builder()
        file_name = self.ui_manager.glade_files['time_picker']
        builder.add_from_file(file_name)
        self.time_popup = builder.get_object('time_date_popup')
        self.date_calendar = builder.get_object('date_calendar')
        self.hour_spin = builder.get_object('hour_spin')
        self.minute_spin = builder.get_object('minute_spin')
        self.second_spin = builder.get_object('second_spin')
        set_button = builder.get_object('set_button')
        reset_button = builder.get_object('reset_button')

        self.time_popup.set_transient_for(self.parent_window)
        self.time_popup.show()

        # Set the position for the time-picker popup
        parent_position = self.parent_window.get_position()
        cursor_position = self.parent_window.get_pointer()
        top_left_x = parent_position[0] + cursor_position[0]
        top_left_y = parent_position[1] + cursor_position[1]
        self.time_popup.move(top_left_x, top_left_y)

        # Move it if near the bottom or right screen borders
        screen = self.time_popup.get_screen()
        screen_width = screen.get_width()
        screen_height = screen.get_height()
        
        popup_width, popup_height = self.time_popup.get_size()
        if top_left_x + popup_width > screen_width:
            top_left_x = screen_width - popup_width
            self.time_popup.move(top_left_x, top_left_y)
        if top_left_y + popup_height > screen_height:
            top_left_y = screen_height - popup_height
            self.time_popup.move(top_left_x, top_left_y)

        # Initialize the time
        time_value = self.targets_dict[target]
        if time_value is None:
            crt_time = datetime.datetime.fromtimestamp(time.time())
        else:
            crt_time = datetime.datetime.fromtimestamp(time_value)
        self.date_calendar.select_month(crt_time.month - 1, crt_time.year)
        self.date_calendar.select_day(crt_time.day)
        self.hour_spin.set_value(crt_time.hour)
        self.minute_spin.set_value(crt_time.minute)
        self.second_spin.set_value(crt_time.second)

        # Connect the handlers
        self.parent_window.connect('focus-out-event',\
                                   self.on_parent_window_focus_out)
        self.parent_window.connect('button-press-event',\
                                   self.on_parent_window_button_press)
        self.time_popup.connect('destroy', self.on_time_popup_destroyed)
        set_button.connect('clicked', self.on_time_set_clicked, target)
        reset_button.connect('clicked', self.on_time_reset_clicked, target)


    def on_time_popup_destroyed(self, time_popup):
        self.time_popup = None


    def on_time_set_clicked(self, set_button, target):
        # Get the time information
        year, month, day = self.date_calendar.get_date()
        hour = self.hour_spin.get_value_as_int()
        minute = self.minute_spin.get_value_as_int()
        second = self.second_spin.get_value_as_int()

        # Because the returned month is in 0-11 range
        month += 1

        date_time = datetime.datetime(year, month, day, hour, minute, second)
        
        self.targets_dict[target] = time.mktime(date_time.timetuple())
        self.emit('value-changed', target, self.targets_dict[target])

        self.time_popup.destroy()


    def on_time_reset_clicked(self, reset_button, target):
        self.targets_dict[target] = None
        self.emit('value-changed', target, -1.0)
        self.time_popup.destroy()


    def on_parent_window_focus_out(self, parent_window, event):
        if self.time_popup is not None:
            self.time_popup.destroy()


    def on_parent_window_button_press(self, parent_window, event):
        if self.time_popup is None:
            return
        if event.type == gtk.gdk.BUTTON_PRESS:
            self.time_popup.destroy()

