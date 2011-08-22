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

from umit.inventory.version import VERSION
from umit.inventory.paths import AGENT_BIN, SERVER_BIN, GUI_BIN,\
        AGENT_MISC_DIR, SERVER_MISC_DIR, GUI_MISC_DIR,\
        PIXMAPS_DIR, CONFIG_DIR, ICONS_DIR, GLADE_DIR

from distutils.core import setup
from distutils.command.sdist import sdist
from distutils.command.install import install
from distutils.filelist import FileList
from glob import glob
import os
import sys


print '\n%s Umit Network Inventory Setup %s\n' % (10 * '#', 10 * '#')


# Umit NI setup.py command classes definitions

class umit_ni_agent_sdist(sdist):

    def run(self):

        self.manifest = "MANIFEST_AGENT"
        self.template = "MANIFEST_AGENT.in"

        self.filelist = FileList()
        self.check_metadata()
        self.get_file_list()
        self.make_distribution()



class umit_ni_server_sdist(sdist):

    def run(self):

        self.manifest = "MANIFEST_SERVER"
        self.template = "MANIFEST_SERVER.in"

        self.filelist = FileList()
        self.check_metadata()
        self.get_file_list()
        self.make_distribution()



class umit_ni_gui_sdist(sdist):

    def run(self):

        self.manifest = "MANIFEST_GUI"
        self.template = "MANIFEST_GUI.in"

        self.filelist = FileList()
        self.check_metadata()
        self.get_file_list()
        self.make_distribution()


# The commands accepted by the Umit NI setup.py
cmdclasses = {
    'sdist_agent' : umit_ni_agent_sdist,
    'sdist_server' : umit_ni_server_sdist,
    'sdist_gui' : umit_ni_gui_sdist,
    'install_agent' : install,
    'install_server' : install,
    'install_gui' : install,
}

# The data files used by the Umit NI Server
ni_server_datafiles = [
    (CONFIG_DIR, [os.path.join(CONFIG_DIR, "umit_server.conf")]),
    (ICONS_DIR, glob(os.path.join(ICONS_DIR, "*"))),
    (SERVER_MISC_DIR, glob(os.path.join(SERVER_MISC_DIR, "*"))),
]

# The data files used by the Umit NI Agent
ni_agent_datafiles = [
    (CONFIG_DIR, [os.path.join(CONFIG_DIR, "umit_agent.conf")]),
    (ICONS_DIR, glob(os.path.join(ICONS_DIR, "*"))),
    (AGENT_MISC_DIR, glob(os.path.join(AGENT_MISC_DIR, "*"))),
]

# The data files used by the Umit NI GUI
ni_gui_datafiles = [
    (CONFIG_DIR, [os.path.join(CONFIG_DIR, "umit_ni_gui.conf")]),
    (PIXMAPS_DIR, glob(os.path.join(PIXMAPS_DIR, "*"))),
    (GLADE_DIR, glob(os.path.join(GLADE_DIR, "*.glade"))),
    (ICONS_DIR, glob(os.path.join(ICONS_DIR, "*"))),
    (GUI_MISC_DIR, glob(os.path.join(GUI_MISC_DIR, "*"))),
]

# NI Agent setup options
agent_setup_options = dict(
    name = 'umit-ni-agent',
    license = 'GNU GPL (version 2 or later)',
    url = 'http://www.umitproject.org',
    download_url = 'http://www.umitproject.org',
    author = 'Dragos Dena',
    author_email = 'dragos.dena@gmail.com',
    version = VERSION,
    packages = ['umit.inventory', 'umit.inventory.agent',
                'umit.inventory.modules.agent', 'umit',
                'umit.inventory.modules'],
    scripts = [AGENT_BIN],
    data_files = ni_agent_datafiles,
    cmdclass = cmdclasses,
    description = "Umit Network Inventory Agent is a daemon that collects"\
                  " information about the host on which it's installed."
)

# NI Server setup options
server_setup_options = dict(
    name = 'umit-ni-server',
    license = 'GNU GPL (version 2 or later)',
    url = 'http://www.umitproject.org',
    download_url = 'http://www.umitproject.org',
    author = 'Dragos Dena',
    author_email = 'dragos.dena@gmail.com',
    version = VERSION,
    packages = ['umit.inventory', 'umit.inventory.server',
                'umit.inventory.modules.server', 'umit',
                'umit.inventory.modules'],
    scripts = [SERVER_BIN],
    data_files = ni_server_datafiles,
    cmdclass = cmdclasses,
    description = "Umit Network Inventory Server is a daemon that stores"\
                  " notifications and various information from the hosts in"\
                  " the network."
)

# NI GUI setup options
gui_setup_options = dict(
    name = 'umit-ni-gui',
    license = 'GNU GPL (version 2 or later)',
    url = 'http://www.umitproject.org',
    download_url = 'http://www.umitproject.org',
    author = 'Dragos Dena',
    author_email = 'dragos.dena@gmail.com',
    version = VERSION,
    packages = ['umit.inventory', 'umit.inventory.gui',
                'umit.inventory.modules.gui', 'umit',
                'umit.inventory.modules'],
    scripts = [GUI_BIN],
    data_files = ni_gui_datafiles,
    cmdclass = cmdclasses,
    description = "Umit Network Inventory GUI shows the information found in "\
                  "the Umit Network Inventory Server trough a friendly user"\
                  " interface."
)

# Saves the data directory to the registry
def windows_data_dir_install(data_dir, target):
    import _winreg
    from umit.inventory.registry_path import registry_path

    reg = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
    key = _winreg.CreateKey(reg, registry_path)
    try:
        entry_name = "DataDir" + str(target).capitalize()
        entry_value = str(data_dir)
        _winreg.SetValueEx(key, entry_name, 0, _winreg.REG_SZ, entry_value)
    except EnvironmentError:
        print "ERROR: Writing to registry failed. The installation is corrupt!"
    _winreg.CloseKey(reg)
    _winreg.CloseKey(key)


# Saves the data directory in a file
def posix_data_dir_install(data_dir, target):
    if os.name != 'posix':
        print "ERROR: Unsupported operating system."
        sys.exit()
    # TODO


if os.name == 'nt':
    data_dir_install = windows_data_dir_install
else:
    data_dir_install = posix_data_dir_install


if 'install_agent' in sys.argv or 'sdist_agent' in sys.argv:
    dist = setup(**agent_setup_options)
    if 'install_agent' in sys.argv:
        data_dir_install(dist.command_obj['install_data'].install_dir, 'agent')
        
    sys.exit()


if 'py2exe_agent' in sys.argv:
    from umit_ni_py2exe import umit_ni_agent_build_exe, \
        agent_build_exe_options, agent_build_exe_data_files
    ni_agent_datafiles += agent_build_exe_data_files
    agent_setup_options.update(agent_build_exe_options)
    cmdclasses['py2exe_agent'] = umit_ni_agent_build_exe
    setup(**agent_setup_options)
    sys.exit()


if 'install_gui' in sys.argv or 'sdist_gui' in sys.argv:
    dist = setup(**gui_setup_options)
    if 'install_gui' in sys.argv:
        data_dir_install(dist.command_obj['install_data'].install_dir, 'gui')
    sys.exit()


if 'py2exe_gui' in sys.argv:
    from umit_ni_py2exe import umit_ni_gui_build_exe, \
        gui_build_exe_options, gui_build_exe_data_files
    ni_gui_datafiles += gui_build_exe_data_files
    gui_setup_options.update(gui_build_exe_options)
    cmdclasses['py2exe_gui'] = umit_ni_gui_build_exe
    setup(**gui_setup_options)
    sys.exit()


if 'install_server' in sys.argv or 'sdist_server' in sys.argv:
    dist = setup(**server_setup_options)
    if 'server_agent' in sys.argv:
        data_dir_install(dist.command_obj['install_data'].install_dir, 'server')
    sys.exit()


if 'py2exe_server' in sys.argv:
    from umit_ni_py2exe import umit_ni_server_build_exe, \
        server_build_exe_options, server_build_exe_data_files
    ni_server_datafiles += server_build_exe_data_files
    server_setup_options.update(server_build_exe_options)
    cmdclasses['py2exe_server'] = umit_ni_server_build_exe
    setup(**server_setup_options)
    sys.exit()


print "Error: Invalid command.\n"
print "Accepted commands:\n"\
      " install_agent: Installs the Umit Network Inventory Agent\n"\
      " install_server: Installs the Umit Network Inventory Server\n"\
      " install_gui: Installs the Umit Network Inventory GUI\n"\
      " sdist_agent: Distributes the Umit Network Inventory Agent\n"\
      " sdist_server: Distributes the Umit Network Inventory Server\n"\
      " sdist_gui: Distributes the Umit Network Inventory GUI\n"