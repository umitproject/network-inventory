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

import sys
from umit.inventory.gui.Configs import NIConfig
from umit.inventory.gui.Core import NICore

import pygtk
import gtk
pygtk.require("2.0")


def main(args):
    """The Umit Notifications Server GUI main function"""
#    builder = gtk.Builder()
#    builder.add_from_file("umit/inventory/gui/glade_files/ni_auth_window.glade")
#    builder.connect_signals({ "on_window_destroy" : gtk.main_quit })
#    window = builder.get_object("auth_window")
#    window.show()
#    gtk.main()

    # Initialize the configurations
    conf = NIConfig()

    # Initialize and start the GUI Core
    core = NICore(conf)
    core.run()
    

if __name__=="__main__":
    main(sys.argv)
