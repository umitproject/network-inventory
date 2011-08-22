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

__all__ = ['agent_build_exe_options', 'agent_build_exe_data_files',
           'server_build_exe_options', 'server_build_exe_data_files']

import sys
import os
from glob import glob
from umit.inventory.paths import UMIT_NI_AGENT_MODULES, UMIT_NI_SERVER_MODULES,\
    UMIT_NI_GUI_MODULES, ICONS_DIR

from py2exe.build_exe import py2exe as build_exe

# Add the bin to the sys.path
file_path = os.path.abspath(os.path.dirname(__file__))
bin_path = os.path.join(file_path, 'bin')
sys.path.append(bin_path)


class umit_ni_agent_build_exe(build_exe):

    def run(self):
        build_exe.run(self)
        # reserved for future development


class umit_ni_server_build_exe(build_exe):

    def run(self):
        build_exe.run(self)
        # reserved for future development


class umit_ni_gui_build_exe(build_exe):

    def run(self):
        # Make the gtkrc
        dir_path = os.path.join('dist', 'etc', 'gtk-2.0')
        try:
            os.makedirs(dir_path)
        except:
            pass
        gtkrc_f = open(os.path.join(dir_path, 'gtkrc'), 'w')
        gtkrc_f.write('gtk-theme-name = "MS-Windows"\n')
        gtkrc_f.write('gtk-icon-theme-name = "hicolor"\n')
        gtkrc_f.write('gtk-button-images = 1\n')
        gtkrc_f.close()

        build_exe.run(self)


agent_build_exe_options = dict(
    zipfile = None,
    service = [{'modules': ['umit_ni_agent'], 'cmdline_style' : 'custom'}],
    options = {"py2exe": {
        "compressed": 1,
        "optimize": 2,
        "includes" : ['umit.inventory.modules.agent.*',],
            }
        },
)

server_build_exe_options = dict(
    zipfile = None,
    service = [{'modules': ['umit_ni_server'], 'cmdline_style' : 'custom'}],
    options = {"py2exe": {
        "compressed": 1,
        "optimize": 2,
        "includes" : ['umit.inventory.modules.server.*',],
            }
        },
)

gui_build_exe_options = dict(
    zipfile = None,
#    service = [{'windows': ['umit_ni_gui'], 'cmdline_style' : 'custom'}],
    windows=[
        {
            'script' : os.path.join('bin', 'umit_ni_gui.py'),
            'icon_resources' : [(1, os.path.join(ICONS_DIR, 'umit_48.ico'))]
        },
    ],
    options = {"py2exe": {
        "compressed": 1,
        "optimize": 2,
        'packages': ['encodings'],
        "includes" : ['umit.inventory.modules.gui.*', 'pango', 'atk',
                      'gobject', 'pickle', 'bz2', 'gio', 'encodings',
                      'encodings.*', 'cairo', 'pangocairo'],
            }
        },
)

agent_build_exe_data_files = [
    (UMIT_NI_AGENT_MODULES, glob(os.path.join(UMIT_NI_AGENT_MODULES, "*.py"))),
]

server_build_exe_data_files = [
    (UMIT_NI_SERVER_MODULES, glob(os.path.join(UMIT_NI_SERVER_MODULES, "*.py"))),
]

gui_build_exe_data_files = [
    (UMIT_NI_GUI_MODULES, glob(os.path.join(UMIT_NI_GUI_MODULES, "*.py"))),
]
