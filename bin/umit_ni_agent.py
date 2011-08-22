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
import logging

if os.getcwd()  not in sys.path:
    sys.path.append(os.getcwd())

# Used to import packaged modules dependencies when using py2exe
if os.name == 'nt':
    import umit.inventory.modules.agent_modules

from umit.inventory.agent.Configs import AgentConfig
from umit.inventory.Configuration import InventoryConfig
from umit.inventory.agent import Core
from umit.inventory import Logger
from umit.inventory.paths import CONFIG_DIR, AGENT_MISC_DIR

# A pointer to the agent main loop
agent_main_loop = None

# ----- Parse arguments ------

# Look if the data dir was set
data_dir = None
for arg in sys.argv:
    if arg.startswith('--data-dir='):
        data_dir = arg.split('=')[1]
        break


# Look if there was an install daemon request.
# This will install the Umit NI Agent as a daemon on Unix systems and
# as a Service on Windows.
install_daemon = ('--install-daemon' in sys.argv)
if not install_daemon:
    install_daemon = ('--install-service' in sys.argv)


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

# ----- Parse Arguments End ------

# If the debug mode is on and there isn't any data directory specified,
# try to get them from the current folder.
if data_dir is None and debug_mode:
    data_dir = '.'

# If the system is NT, try to add the InstallPathAgent registry entry to the
# Python path.
if os.name == 'nt':
    import _winreg
    from umit.inventory.registry_path import registry_path

    try:
        reg = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
        key = _winreg.OpenKey(reg, registry_path)
        python_path_value, python_path_type =\
            _winreg.QueryValueEx(key, 'InstallPathAgent')
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
        data_dir_value, data_dir_type = _winreg.QueryValueEx(key, "DataDirAgent")
        data_dir = str(data_dir_value)


# Get the config file path
conf_path = None
if data_dir is not None and os.name is 'nt':
    conf_path = os.path.join(data_dir, CONFIG_DIR, 'umit_agent.conf')
if data_dir is None and os.name == 'nt':
    print 'Error: Can\'t find configuration file'
    sys.exit()

if os.name is 'posix':
    if not debug_mode:
        conf_path = '/etc/umit_agent.conf'
        conf = AgentConfig(config_file_path=conf_path)
        data_dir = conf.get(InventoryConfig.general_section, 'data_dir')
    else:
        conf_path = os.path.join(CONFIG_DIR, 'umit_agent.conf')


# Launch the agent in debug mode
if debug_mode:
    conf = AgentConfig(config_file_path=conf_path)

    real_log_level = 'debug'
    if log_level is not None:
        real_log_level = log_level
    Logger.init_logger(conf, log_level=real_log_level, log_to_console=True)
    
    parser = Core.AgentNotificationParser(conf)

    # The agent main loop
    agent_main_loop = Core.AgentMainLoop(parser, conf)
    agent_main_loop.set_data_dir(data_dir)
    agent_main_loop.run()


# Run as a Windows Service
if os.name == 'nt' and not debug_mode:
    from umit.inventory.Service import UmitService

    
    class UmitAgentService(UmitService):
        
        _svc_name_ = 'umitagent'
        _svc_display_name_ = 'Umit Agent'
        _svc_description_ = 'Listens for host events and generates notifications'

        _file = __file__
        
        def start(self):
            # The Agent Configurations. See umit/inventory/agent/Configs.py
            # for details regarding the configuration file location and default
            # settings.
            log_path = os.path.join(data_dir, 'logs')
            conf = AgentConfig(config_file_path=conf_path,
                               default_log_path=log_path)

            # Init the logging
            Logger.init_logger(conf, log_level=log_level, log_to_console=True)
            # The message Parser which will encrypt (if specified) and send the
            # messages.
            parser = Core.AgentNotificationParser(conf)

            # The agent main loop
            self.agent_main_loop = Core.AgentMainLoop(parser, conf)
            self.agent_main_loop.set_data_dir(data_dir)
            self.agent_main_loop.run()

        def stop(self):
            if hasattr(self, 'agent_main_loop'):
                self.agent_main_loop.shutdown()


    # Service command line handle
    if install_daemon or 'install' in sys.argv:
        print 'Installing Umit Agent Service ...'
        try:
            UmitService.install(UmitAgentService)
            print 'Umit Agent Service installed succesfully'
        except:
            import traceback
            traceback.print_exc()
            print '\nInstalling FAILED'
        print 'Press any key to exit ...'
        sys.stdin.read(1)


    if 'start' in sys.argv:
        print 'Starting Umit Agent Service ...'
        try:
            UmitService.start_service(UmitAgentService._svc_name_)
            print 'Umit Agent Service started succesfully'
        except:
            import traceback
            traceback.print_exc()
            print '\nStarting service FAILED'


    if 'stop' in sys.argv:
        print 'Stopping Umit Agent Service ...'
        try:
            UmitService.stop_service(UmitAgentService._svc_name_)
            print 'Umit Agent Service stopped succesfully'
        except:
            import traceback
            traceback.print_exc()
            print '\nStopping service FAILED'


    def HandleCommandLine():
        pass



def posix_exit_handler(args):
    global agent_main_loop
    if isinstance(agent_main_loop, Core.AgentMainLoop):
        agent_main_loop.shutdown()


# Run as an UNIX daemon
if os.name == 'posix' and not debug_mode:
    from umit.inventory.Daemon import daemonize
    if not daemonize('agent', posix_exit_handler):
        print '\nERROR: Failed daemonizing.\n'

    conf = AgentConfig(config_file_path=conf_path)

    Logger.init_logger(conf, log_level=log_level, log_to_console=False)

    parser = Core.AgentNotificationParser(conf)

    # The agent main loop
    global agent_main_loop
    agent_main_loop = Core.AgentMainLoop(parser, conf)
    agent_main_loop.set_data_dir(data_dir)
    agent_main_loop.run()
    logging.info('Stopped')


if os.name not in ['posix', 'nt']:
    print 'ERROR: Operating System not supported.'

