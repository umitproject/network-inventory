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
import os
import cairo
import gio
import gobject
import gtk
import pango
import pangocairo
import atk
import bz2

from umit.inventory.gui.Configs import NIConfig
from umit.inventory.gui.Core import NICore
from umit.inventory.paths import CONFIG_DIR, GLADE_DIR, ICONS_DIR, GUI_MISC_DIR

import pygtk
pygtk.require("2.0")

if os.name == 'nt':
    import umit.inventory.modules.gui_modules


if "." not in sys.path:
    sys.path.append(".")

# ----- Parse arguments ------

# Look if the data dir was set
data_dir = None
for arg in sys.argv:
    if arg.startswith('--data-dir='):
        data_dir = arg.split('=')[1]
        break

# Look if there was a debug run mode request.
debug_mode = ('--debug-mode' in sys.argv)

# ----- Parse Arguments End ------


# If the debug mode is on and there isn't any data directory specified,
# try to get them from the current folder.
if data_dir is None and debug_mode:
    data_dir = '.'

# If the system is NT, try to add the InstallPathGUI registry entry to the
# Python path.
if os.name == 'nt':
    import _winreg
    from umit.inventory.registry_path import registry_path

    try:
        reg = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
        key = _winreg.OpenKey(reg, registry_path)
        python_path_value, python_path_type =\
            _winreg.QueryValueEx(key, 'InstallPathGUI')
        if python_path_value not in sys.path:
            sys.path.append(python_path_value)
    except:
        pass


# If the debug mode is off and there isn't any data directory specified,
# try to get them from a platform dependent location.
if data_dir is None and not debug_mode:
    if os.name == 'nt':
        # Get it from registry
        import _winreg
        from umit.inventory.registry_path import registry_path

        reg = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
        key = _winreg.OpenKey(reg, registry_path)
        data_dir_value, data_dir_type = _winreg.QueryValueEx(key, "DataDirGUI")
        data_dir = str(data_dir_value)

    if os.name == 'posix':
        # Try to get them with base path being "/" or "/usr", else fail
        base_path = "/usr"
        paths_ok = True
        if not os.path.exists(os.path.join(base_path, CONFIG_DIR)):
            paths_ok = False
        if not os.path.exists(os.path.join(base_path, GUI_MISC_DIR)):
            paths_ok = False

        if paths_ok:
            data_dir = "/usr"

        if not paths_ok:
            base_path = "/"
            paths_ok = True
            if not os.path.exists(os.path.join(base_path, CONFIG_DIR)):
                paths_ok = False
            if not os.path.exists(os.path.join(base_path, GUI_MISC_DIR)):
                paths_ok = False

            if paths_ok:
                data_dir = "/"


# Get the config file path
conf_path = None
if data_dir is not None:
    conf_path = os.path.join(data_dir, CONFIG_DIR, 'umit_ni_gui.conf')


# Start the GUI
conf = NIConfig(config_file_path=conf_path)

core = NICore(conf, data_dir)
core.run()
