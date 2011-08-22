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

import os

BIN_DIRNAME = 'bin'
AGENT_BIN = os.path.join(BIN_DIRNAME, 'umit_ni_agent.py')
SERVER_BIN = os.path.join(BIN_DIRNAME, 'umit_ni_server.py')
GUI_BIN = os.path.join(BIN_DIRNAME, 'umit_ni_gui.py')

UMIT_MAIN = 'umit'
UMIT_INVENTORY_MAIN = os.path.join('umit', 'inventory')
UMIT_NI_AGENT_MAIN = os.path.join(UMIT_INVENTORY_MAIN, 'agent')
UMIT_NI_SERVER_MAIN = os.path.join(UMIT_INVENTORY_MAIN, 'server')
UMIT_NI_GUI_MAIN = os.path.join(UMIT_INVENTORY_MAIN, 'gui')

UMIT_NI_MODULES = os.path.join(UMIT_INVENTORY_MAIN, 'modules')
UMIT_NI_GUI_MODULES = os.path.join(UMIT_NI_MODULES, 'gui')
UMIT_NI_AGENT_MODULES = os.path.join(UMIT_NI_MODULES, 'agent')
UMIT_NI_SERVER_MODULES = os.path.join(UMIT_NI_MODULES, 'server')

PIXMAPS_DIR = os.path.join('share', 'pixmaps', 'umit', 'inventory')
ICONS_DIR = os.path.join('share', 'icons', 'umit', 'inventory')
CONFIG_DIR = os.path.join('share', 'umit', 'config', 'inventory')
GLADE_DIR = os.path.join('share', 'umit', 'inventory', 'glade_files')
MISC_DIR = os.path.join('share', 'umit', 'inventory', 'misc')
AGENT_MISC_DIR = os.path.join(MISC_DIR, 'agent')
SERVER_MISC_DIR = os.path.join(MISC_DIR, 'server')
GUI_MISC_DIR = os.path.join(MISC_DIR, 'gui')