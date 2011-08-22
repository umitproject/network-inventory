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
import os

class ConfigurationWindowManager:

    SECTIONS_MODEL_COL_PIXBUF = 0
    SECTIONS_MODEL_COL_TEXT = 1
    SECTIONS_MODEL_COL_WIDGET = 2

    def __init__(self, ui_manager):
        self.ui_manager = ui_manager
        self.shell = ui_manager.shell
        self.config_window = None


    def _init_model(self):
        self.sections_model = gtk.ListStore(gobject.TYPE_OBJECT,
                gobject.TYPE_STRING, gobject.TYPE_OBJECT)


    def _build_objects(self):
        glade_file_name = self.ui_manager.get_glade_file_path('ni_config_window.glade')
        builder = gtk.Builder()
        builder.add_from_file(glade_file_name)
        self.config_window = builder.get_object('config_window')
        self.sections_tree_view = builder.get_object('sections_tree_view')
        self.config_widget_container =\
                builder.get_object('config_widget_container')
        self.close_button = builder.get_object('close_button')


    def add_config_page(self, pixbuf, text, widget):
        iter = self.sections_model.append()
        self.sections_model.set(iter,
                                self.SECTIONS_MODEL_COL_TEXT, text,
                                self.SECTIONS_MODEL_COL_PIXBUF, pixbuf,
                                self.SECTIONS_MODEL_COL_WIDGET, widget)
        

    def _init_tree_view(self):
        self.sections_tree_view.set_model(self.sections_model)

        cell = ConfigCellRenderer()
        col = gtk.TreeViewColumn('Sections', cell)
        col.set_alignment(0.5)
        col.set_property('resizable', False)
        col.set_min_width(140)
        col.add_attribute(cell, 'text', self.SECTIONS_MODEL_COL_TEXT)
        col.add_attribute(cell, 'pixbuf', self.SECTIONS_MODEL_COL_PIXBUF)
        self.sections_tree_view.append_column(col)
        self.sections_tree_view.set_headers_visible(False)


    def _init_handlers(self):
        self.close_button.connect('clicked', self.on_close_button_clicked)
        self.sections_tree_view.connect('cursor-changed',
                self.on_sections_tree_view_cursor_changed)
        self.config_window.connect('destroy', self.on_config_window_destroyed)


    def show(self):
        self._init_model()
        self.shell.request_config_pages(self)
        self._build_objects()
        self._init_handlers()
        self._init_tree_view()

        self.config_window.set_transient_for(self.ui_manager.main_window)
        self.config_window.set_modal(True)
        icon = self.ui_manager.main_window.get_icon()
        self.config_window.set_icon(icon)
        self.config_window.show()


    def show_error(self, err_msg, err_title):
        if self.config_window is None:
            return

        error_dialog = gtk.MessageDialog(parent=self.config_window,
                                         type=gtk.MESSAGE_ERROR,
                                         buttons=gtk.BUTTONS_OK)
        icon = self.config_window.get_icon()
        error_dialog.set_icon(icon)
        error_dialog.set_transient_for(self.config_window)
        error_dialog.set_modal(True)
        error_dialog.set_property('text', err_title)
        error_dialog.set_title('Connection Error')
        error_dialog.set_property('secondary-text', err_msg)
        error_dialog.connect('response', self.on_dialog_response)
        error_dialog.show()

    
    # Handlers

    def on_dialog_response(self, dialog, response_id):
        dialog.destroy()
    

    def on_config_window_destroyed(self, config_window):
        self.config_window = None
        

    def on_close_button_clicked(self, close_button):
        self.config_window.destroy()


    def on_sections_tree_view_cursor_changed(self, tree_view):
        # Get the widget corresponding to this path
        path, focus_column = tree_view.get_cursor()
        iter = self.sections_model.get_iter(path)
        
        widget = self.sections_model.get_value(iter,
                                               self.SECTIONS_MODEL_COL_WIDGET)

        # Clear the container
        children = self.config_widget_container.get_children()
        for child in children:
            self.config_widget_container.remove(child)
            child.hide()

        self.config_widget_container.add(widget)
        widget.show()



class ConfigCellRenderer(gtk.CellRenderer):
    __gproperties__ = {
        'inner-padding' : (gobject.TYPE_INT,
                           'cell inner padding',
                           'Padding between the text and the image',
                           0,
                           30,
                           5,
                           gobject.PARAM_READWRITE),
        'pixbuf' : (gobject.TYPE_OBJECT,
                    'cell text',
                    'Cell text',
                    gobject.PARAM_READWRITE),
        'text' : (gobject.TYPE_STRING,
                  'cell text',
                  'Cell text',
                  '',
                  gobject.PARAM_READWRITE)

    }

    def __init__(self):
        self.__gobject_init__()
        self.text_renderer = gtk.CellRendererText()
        self.pixbuf_renderer = gtk.CellRendererPixbuf()
        self.inner_padding = 5


    def do_set_property(self, property, property_value):
        if property.name == 'text':
            self.text_renderer.set_property('text', property_value)
            return
        if property.name == 'pixbuf':
            self.pixbuf_renderer.set_property('pixbuf', property_value)
            return
        if property.name == 'inner-padding':
            self.inner_padding = property_value
            return
        setattr(self, property.name, property_value)
#        gobject.GObject.set_property(self, property.name, property_value)


    def do_get_property(self, property):
        if property.name == 'text':
            return self.text_renderer.get_property('text')
        if property.name == 'pixbuf':
            return self.pixbuf_renderer.get_property('pixbuf')
        if property.name == 'inner-padding':
            return self.inner_padding
        return getattr(self, property.name)
#        return gobject.GObject.get_property(self, property.name)
            

    def do_get_size(self, widget, cell_area=None):
        text_xoff, text_yoff, text_w, text_h =\
                self.text_renderer.get_size(widget, cell_area)

        pixbuf_xoff, pixbuf_yoff, pixbuf_w, pixbuf_h =\
                self.pixbuf_renderer.get_size(widget, cell_area)

        xpad = self.get_property('xpad')
        ypad = self.get_property('ypad')
        xalign = self.get_property('xalign')
        yalign = self.get_property('yalign')

        width = max(text_w, pixbuf_w) + xpad * 2
        height = text_h + pixbuf_h + ypad * 2 + self.inner_padding

        xoffset = 0
        yoffset = 0
        if cell_area is not None:
            cell_w = cell_area.width
            cell_h = cell_area.height
            xoffset = max(xalign * (cell_w - width), 0)
            yoffset = max(yalign * (cell_h - height), 0)
        return xoffset, yoffset, width, height


    def do_render(self, window, widget, background_area, cell_area,
               expose_area, flags):
        text_xoff, text_yoff, text_w, text_h =\
                self.text_renderer.get_size(widget, cell_area)

        pixbuf_xoff, pixbuf_yoff, pixbuf_w, pixbuf_h =\
                self.pixbuf_renderer.get_size(widget, cell_area)

        xpad = self.get_property('xpad')
        ypad = self.get_property('ypad')
        xalign = self.get_property('xalign')
        yalign = self.get_property('yalign')

        cell_w = cell_area.width
        cell_h = cell_area.height
        cell_x = cell_area.x
        cell_y = cell_area.y
        
        pixbuf_x = cell_x + int(xalign * (cell_w - pixbuf_w)) + xpad
        pixbuf_y = cell_y + ypad

        text_x = cell_x + int(xalign * (cell_w - text_w)) + xpad
        text_y = cell_y + ypad + pixbuf_h + self.inner_padding
        

        pixbuf_area = gtk.gdk.Rectangle(pixbuf_x, pixbuf_y, pixbuf_w, pixbuf_h)
        text_area = gtk.gdk.Rectangle(text_x, text_y, text_w, text_h)

        self.text_renderer.render(window, widget, background_area, text_area,
               expose_area, flags)
        self.pixbuf_renderer.render(window, widget, background_area,
                pixbuf_area, expose_area, flags)

gobject.type_register(ConfigCellRenderer)