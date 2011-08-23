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
        PIXMAPS_DIR, CONFIG_DIR, ICONS_DIR, GLADE_DIR, INSTALL_SCRIPTS

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
    (ICONS_DIR, glob(os.path.join(ICONS_DIR, "*"))),
    (SERVER_MISC_DIR, glob(os.path.join(SERVER_MISC_DIR, "*"))),
    (INSTALL_SCRIPTS, glob(os.path.join(INSTALL_SCRIPTS, "*"))),
]


# The data files used by the Umit NI Agent
ni_agent_datafiles = [
    (ICONS_DIR, glob(os.path.join(ICONS_DIR, "*"))),
    (AGENT_MISC_DIR, glob(os.path.join(AGENT_MISC_DIR, "*"))),
    (INSTALL_SCRIPTS, glob(os.path.join(INSTALL_SCRIPTS, "*"))),
]

# The data files used by the Umit NI GUI
ni_gui_datafiles = [
    (PIXMAPS_DIR, glob(os.path.join(PIXMAPS_DIR, "*"))),
    (GLADE_DIR, glob(os.path.join(GLADE_DIR, "*.glade"))),
    (ICONS_DIR, glob(os.path.join(ICONS_DIR, "*"))),
    (GUI_MISC_DIR, glob(os.path.join(GUI_MISC_DIR, "*"))),
    (INSTALL_SCRIPTS, glob(os.path.join(INSTALL_SCRIPTS, "*"))),
]


def update_windows_data_files():
    ni_agent_datafiles.append(
        (CONFIG_DIR, [os.path.join(CONFIG_DIR, "umit_agent.conf")]))
    ni_server_datafiles.append(
        (CONFIG_DIR, [os.path.join(CONFIG_DIR, "umit_server.conf")]))
    ni_gui_datafiles.append(
        (CONFIG_DIR, [os.path.join(CONFIG_DIR, "umit_ni_gui.conf")]))


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


def posix_data_dir_install(data_dir, target):
    pass


def posix_generate_agent_config_files(data_dir):
    import getpass

    print
    print '\n%s Umit Network Inventory Agent Configuration %s\n'\
            % (10 * '#', 10 * '#')

    # Get the SSL enabled option
    encrypt_enabled_txt = 'Should the data transfer with the Notifications Server be encrypted? [y/N]'
    encrypt_enabled = raw_input(encrypt_enabled_txt)
    encrypt_enabled = encrypt_enabled.strip()
    if len(encrypt_enabled) > 0 and encrypt_enabled[0] in ['y', 'Y']:
        encrypt_enabled = True
    else:
        encrypt_enabled = False

    # Get the authentication enabled option. Defaults to yes if ssl is enabled,
    # False otherwise.
    if encrypt_enabled:
        y_n = '[Y/n]'
    else:
        y_n = '[y/N]'
    auth_enabled_txt = 'Should the data transfer with the Notifications Server be authenticated? %s'\
                        % y_n
    auth_enabled = raw_input(auth_enabled_txt)
    auth_enabled = auth_enabled.strip()
    if len(auth_enabled) is 0:
        auth_enabled = encrypt_enabled
    elif auth_enabled[0] in ['n', 'N']:
        auth_enabled = False
    else:
        auth_enabled = True

    # Get the server address
    server_address = raw_input('Enter Notifications Server Address IP: ')

    # Get the server port
    if encrypt_enabled:
        default_port = '20001'
    else:
        default_port = '20000'
    server_port = raw_input('Enter Notifications Server listening port [%s]: ' % default_port)
    server_port = server_port.strip()
    try:
        server_port = int(server_port)
    except:
        server_port = int(default_port)

    # If authentication is enabled get the username and password
    if auth_enabled:
        username = raw_input('Notifications Server Username: ')
        password_not_valid = True
        while password_not_valid:
            password1 = getpass.unix_getpass('Notifications Server Password: ')
            password2 = getpass.unix_getpass('Confirm Notifications Server Password: ')

            password_not_valid = (password1 != password2)
            if password_not_valid:
                print 'Error: Passwords must match.'
                print
            else:
                password = password1

    # Write the settings to the file
    conf_file = open('/etc/umit_agent.conf', 'w')
    conf_file.write('[GeneralSection]\n')
    conf_file.write('ssl_enabled = %s\n' % str(encrypt_enabled))
    conf_file.write('authentication_enabled = %s\n' % str(auth_enabled))
    conf_file.write('server_address = %s\n' % str(server_address))
    conf_file.write('server_port = %s\n' % str(server_port))
    if auth_enabled:
        conf_file.write('username = %s\n' % str(username))
        conf_file.write('password = %s\n' % str(password))
    conf_file.write('data_dir = %s\n' % str(data_dir))
    conf_file.close()

    os.system('umit_ni_agent.py')


def posix_generate_server_config_files(data_dir):
    import getpass

    print
    print '\n%s Umit Network Inventory Server Configuration %s\n'\
            % (10 * '#', 10 * '#')

    # Get the admin password
    password_not_valid = True
    print 'Enter the administrator password associated with the username "admin"'
    while password_not_valid:
        password1 = getpass.unix_getpass('Notifications Server Admin Password: ')
        password2 = getpass.unix_getpass('Confirm Notifications Server Admin Password: ')

        password_not_valid = (password1 != password2)
        if password_not_valid:
            print 'Error: Passwords must match.'
            print
        else:
            admin_password = password1

    # Get the database host
    db_host = raw_input('Enter Mongo Database host [localhost]:')
    db_host = db_host.strip()
    if len(db_host) is 0:
        db_host = 'localhost'

    # Get the database port
    db_port = raw_input('Enter Mongo Database port (blank for default): ')
    db_port = db_port.strip()
    if len(db_port) > 0:
        try:
            db_port = int(db_port)
        except:
            db_port = ''

    # Get the database username
    db_username = raw_input('Enter Mongo Database Username (blank for none): ')
    db_username = db_username.strip()
    
    # Get the database username
    if db_username != '':
        password_not_valid = True
        while password_not_valid:
            password1 = getpass.unix_getpass('Mongo Database Password: ')
            password2 = getpass.unix_getpass('Mongo Database Password: ')

            password_not_valid = (password1 != password2)
            if password_not_valid:
                print 'Error: Passwords must match.'
                print
            else:
                db_password = password1
    else:
        db_password = ''

    # Write the settings to the file
    conf_file = open('/etc/umit_server.conf', 'w')
    conf_file.write('[GeneralSection]\n')
    conf_file.write('interface_port = 30000\n')
    conf_file.write('force_interface_encrypt = False\n')
    conf_file.write('data_dir = %s\n' % str(data_dir))
    conf_file.write('\n')
    conf_file.write('[Database]\n')
    conf_file.write('host = %s\n' % str(db_host))
    conf_file.write('port = %s\n' % str(db_port))
    conf_file.write('username = %s\n' % str(db_username))
    conf_file.write('password = %s\n' % str(db_password))
    conf_file.close()

    # Save the admin password
    os.system('umit_ni_server.py --admin-password=%s' % admin_password)


def posix_generate_gui_config_files(data_dir):
    # Write the settings to the file
    conf_file = open('/etc/umit_ni_gui.conf', 'w')
    conf_file.write('[GeneralSection]\n')
    conf_file.write('data_dir = %s\n' % str(data_dir))
    conf_file.write('enable_encryption_with_notifications_server = True\n')
    conf_file.write('notifications_server_port = 30000\n')
    conf_file.close()


def darwin_generate_agent_plist(script_dir):
    # Open the plist template
    plist_template = open(os.path.join(INSTALL_SCRIPTS, 'umit_agent.plist'), 'r')
    plist_template_str = plist_template.read()
    plist_template.close()

    plist_str = plist_template_str % os.path.join(script_dir, 'umit_ni_agent.py')
    plist = open('umit_agent.plist', 'w')
    plist.write(plist_str)
    plist.close()

    print '\n Generated plist file: umit_agent.plist\n\n'

    
def darwin_generate_server_plist(script_dir):
    # Open the plist template
    plist_template = open(os.path.join(INSTALL_SCRIPTS, 'umit_server.plist'), 'r')
    plist_template_str = plist_template.read()
    plist_template.close()

    plist_str = plist_template_str % os.path.join(script_dir, 'umit_ni_server.py')
    plist = open('umit_server.plist', 'w')
    plist.write(plist_str)
    plist.close()

    print '\n Generated plist file: umit_server.plist\n\n'


def linux_generate_init_script(target, script_dir):
    # Open the init script template
    init_script_template = open(
        os.path.join(INSTALL_SCRIPTS, 'umit_ni_%sd_template' % target), 'r')
    init_script_template_str = init_script_template.read()
    init_script_template.close()

    # Generate the init script
    init_script_str = init_script_template_str %\
        os.path.join(script_dir, 'umit_ni_%s.py' % target)
    init_script_path = '/etc/init.d/umit_ni_%sd' % target
    init_script = open(init_script_path, 'w')
    init_script.write(init_script_str)
    init_script.close()

    os.chmod(init_script_path, 0777)


if os.name == 'nt':
    data_dir_install = windows_data_dir_install
else:
    data_dir_install = posix_data_dir_install


if 'install_agent' in sys.argv or 'sdist_agent' in sys.argv:
    # Added the windows data files if we are packaging or installing on a
    # windows machine.
    if os.name == 'nt' or 'sdist_agent' in sys.argv:
        update_windows_data_files()

    dist = setup(**agent_setup_options)
    
    if 'install_agent' in sys.argv:
        data_dir = dist.command_obj['install_data'].install_dir
        script_dir = dist.command_obj['install_scripts'].install_dir
        data_dir_install(data_dir, 'agent')

        if os.name == 'posix':
            posix_generate_agent_config_files(data_dir)

        if sys.platform is 'darwin':
            darwin_generate_agent_plist(script_dir)

        if sys.platform.startswith('linux'):
            linux_generate_init_script('agent', script_dir)

    sys.exit()


if 'py2exe_agent' in sys.argv:
    from umit_ni_py2exe import umit_ni_agent_build_exe, \
        agent_build_exe_options, agent_build_exe_data_files
    ni_agent_datafiles += agent_build_exe_data_files
    agent_setup_options.update(agent_build_exe_options)
    cmdclasses['py2exe_agent'] = umit_ni_agent_build_exe
    update_windows_data_files()
    setup(**agent_setup_options)
    sys.exit()


if 'install_gui' in sys.argv or 'sdist_gui' in sys.argv:
    # Added the windows data files if we are packaging or installing on a
    # windows machine.
    if os.name == 'nt' or 'sdist_gui' in sys.argv:
        update_windows_data_files()

    dist = setup(**gui_setup_options)
    if 'install_gui' in sys.argv:
        data_dir = dist.command_obj['install_data'].install_dir
        data_dir_install(data_dir, 'gui')

        if os.name == 'posix':
            posix_generate_gui_config_files(data_dir)

    sys.exit()


if 'py2exe_gui' in sys.argv:
    from umit_ni_py2exe import umit_ni_gui_build_exe, \
        gui_build_exe_options, gui_build_exe_data_files
    ni_gui_datafiles += gui_build_exe_data_files
    gui_setup_options.update(gui_build_exe_options)
    cmdclasses['py2exe_gui'] = umit_ni_gui_build_exe
    update_windows_data_files()
    setup(**gui_setup_options)
    sys.exit()


if 'install_server' in sys.argv or 'sdist_server' in sys.argv:
    # Added the windows data files if we are packaging or installing on a
    # windows machine.
    if os.name == 'nt' or 'sdist_server' in sys.argv:
        update_windows_data_files()

    dist = setup(**server_setup_options)
    if 'install_server' in sys.argv:
        data_dir = dist.command_obj['install_data'].install_dir
        script_dir = dist.command_obj['install_scripts'].install_dir
        data_dir_install(data_dir, 'server')

        if os.name == 'posix':
            posix_generate_server_config_files(data_dir)

        if sys.platform == 'darwin':
            darwin_generate_server_plist(script_dir)

        if sys.platform.startswith('linux'):
            linux_generate_init_script('server', script_dir)

    sys.exit()


if 'py2exe_server' in sys.argv:
    from umit_ni_py2exe import umit_ni_server_build_exe, \
        server_build_exe_options, server_build_exe_data_files
    ni_server_datafiles += server_build_exe_data_files
    server_setup_options.update(server_build_exe_options)
    cmdclasses['py2exe_server'] = umit_ni_server_build_exe
    update_windows_data_files()
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
