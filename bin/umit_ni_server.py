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

from umit.inventory.server.Configs import ServerConfig
from umit.inventory.server.Core import ServerCore
from umit.inventory import Logger
from umit.inventory.paths import CONFIG_DIR, SERVER_MISC_DIR

# Used to import packaged modules dependencies when using py2exe
if os.name == 'nt':
    import umit.inventory.modules.server_modules

if "." not in sys.path:
    sys.path.append(".")

# Pointer to the server core
server_core = None

# ----- Parse arguments ----------

# Look if the data dir was set
data_dir = None
for arg in sys.argv:
    if arg.startswith('--data-dir='):
        data_dir = arg.split('=')[1]
        break

# Look if there was a debug run mode request.
debug_mode = ('--debug-mode' in sys.argv)

# Look if there was a log level request.
log_level = None
for arg in sys.argv:
    if arg.startswith('--log-level='):
        log_level = arg.split('=')[1]
        break
if log_level not in ['info', 'debug', 'warning', 'critical', 'error']:
    log_level = None

# Look if there was an install daemon request.
# This will install the Umit NI Agent as a daemon on Unix systems and
# as a Service on Windows.
install_daemon = ('--install-daemon' in sys.argv)
if not install_daemon:
    install_daemon = ('--install-service' in sys.argv)

# If there is a request to set the admin password.
admin_password = None
for arg in sys.argv:
    if arg.startswith('--admin-password='):
        admin_password = arg.split('=')[1]
        break
if admin_password is not None and install_daemon:
    print "Error: Can't set the admin password with --install-daemon option"
    admin_password = None

# ----- Parse arguments End ------

# If the debug mode is on and there isn't any data directory specified,
# try to get them from the current folder.
if data_dir is None and debug_mode:
    data_dir = '.'

# Get the config file path
conf_path = None
if data_dir is not None:
    conf_path = os.path.join(data_dir, CONFIG_DIR, 'umit_server.conf')

# If the system is NT, try to add the InstallPathServer registry entry to the
# Python path.
if os.name == 'nt':
    import _winreg
    from umit.inventory.registry_path import registry_path

    try:
        reg = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
        key = _winreg.OpenKey(reg, registry_path)
        python_path_value, python_path_type =\
            _winreg.QueryValueEx(key, 'InstallPathServer')
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
        data_dir_value, data_dir_type = _winreg.QueryValueEx(key, "DataDirServer")
        data_dir = str(data_dir_value)

    if os.name == 'posix':
        # Try to get them with base path being "/" or "/usr", else fail
        base_path = "/usr"
        paths_ok = True
        if not os.path.exists(os.path.join(base_path, CONFIG_DIR)):
            paths_ok = False
        if not os.path.exists(os.path.join(base_path, SERVER_MISC_DIR)):
            paths_ok = False

        if paths_ok:
            data_dir = "/usr"

        if not paths_ok:
            base_path = "/"
            paths_ok = True
            if not os.path.exists(os.path.join(base_path, CONFIG_DIR)):
                paths_ok = False
            if not os.path.exists(os.path.join(base_path, SERVER_MISC_DIR)):
                paths_ok = False

            if paths_ok:
                data_dir = "/"


# Get the config file path
conf_path = None
if data_dir is not None:
    conf_path = os.path.join(data_dir, CONFIG_DIR, 'umit_server.conf')


# Start the server in debug mode
if debug_mode:
    # The Server Configurations. See umit/inventory/agent/Configs.py
    # for details regarding the configuration file location and default
    # settings
    conf = ServerConfig(config_file_path=conf_path)

    # Init the logging
    real_log_level = 'debug'
    if log_level is not None:
        real_log_level = log_level
    Logger.init_logger(conf, log_level=real_log_level, log_to_console=True)

    # Load the Core based on the configs.
    core = ServerCore(conf)

    if admin_password is not None:
        core.set_admin_password(admin_password)

    # Run the Core.
    core.run()


if os.name == 'nt' and not debug_mode:
    from umit.inventory.Service import UmitService

    
    class UmitServerService(UmitService):

        _svc_name_ = 'umit_ni_server'
        _svc_display_name_ = 'Umit Notifications Server'
        _svc_description_ = 'Stores network notifications and allows other '\
                            'applications to connect and view the data.'

        _file = __file__

        def start(self):
            # Try to start the mongo service in case it wasn't started by Windows
            try:
                UmitService.start_service('MongoDB')
            except:
                pass
            log_path = os.path.join(data_dir, 'logs')
            conf = ServerConfig(config_file_path=conf_path,
                                default_log_path=log_path)

            # Init the logging
            Logger.init_logger(conf, log_level=log_level, log_to_console=True)

            # Load the Core based on the configs.
            self.core = ServerCore(conf)

            # Run the Core.
            self.core.run()


        def stop(self):
            if hasattr(self, 'core') and isinstance(self.core, ServerCore):
                self.core.shutdown()


    # Service command line handle
    if install_daemon or 'install' in sys.argv:
        # If we have an admin password set request try setting the admin
        # password
        # Try to start the mongo service in case it wasn't started by Windows
        try:
            UmitService.start_service('MongoDB')
        except:
            pass
        if admin_password is not None:
            try:
                conf = ServerConfig(config_file_path=conf_path)
                core = ServerCore(conf)
                core.set_admin_password(admin_password)
            except:
                pass

        print 'Installing Umit Server Service ...'
        try:
            UmitService.install(UmitServerService)
            print 'Umit Server Service installed succesfully'
        except:
            import traceback
            traceback.print_exc()
            print '\nInstalling FAILED'
        print '\nPress any key to exit ...'
        sys.stdin.read(1)


    if 'start' in sys.argv:
        print 'Starting Umit Server Service ...'
        try:
            UmitService.start_service(UmitServerService._svc_name_)
            print 'Umit Server Service started succesfully'
        except:
            import traceback
            traceback.print_exc()
            print '\nStarting service FAILED'


    if 'stop' in sys.argv:
        print 'Stopping Umit Server Service ...'
        try:
            UmitService.stop_service(UmitServerService._svc_name_)
            print 'Umit Server Service stopped succesfully'
        except:
            import traceback
            traceback.print_exc()
            print '\nStopping service FAILED'


    def HandleCommandLine():
        pass



def posix_exit_handler(args):
    global server_core
    if isinstance(server_core, ServerCore):
        server_core.shutdown()


if os.name == 'posix' and not debug_mode:
    from umit.inventory.Daemon import daemonize
    daemonize('server', posix_exit_handler)
    
    conf = ServerConfig(config_file_path=conf_path)

    Logger.init_logger(conf, log_level=log_level, log_to_console=False)

    # Load the Core based on the configs.
    global server_core
    server_core = ServerCore(conf)

    if admin_password is not None:
        server_core.set_admin_password(admin_password)

    # Run the Core.
    server_core.run()


if os.name not in ['nt', 'posix']:
    print 'Error: Operating System not supported.'