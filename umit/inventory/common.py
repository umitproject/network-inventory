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

import logging
import sys
import os
import imp
from glob import glob

from umit.inventory.paths import UMIT_NI_MODULES


# The message delimiter used for TCP communication
message_delimiter = '\x00\x01\x02\x03'

# The time interval between consecutive KEEP_ALIVE Agent messages.
# An Agent is considered down if the Notifications Server doesn't receive
# a KEEP_ALIVE message in 3 times. It's expressed in number of seconds.
keep_alive_timeout = 30.0


class NotificationTypes:

    info = "INFO"
    recovery = "RECOVERY"
    warning = "WARNING"
    critical = "CRITICAL"
    security = "SECURITY"
    unknown = "UNKNOWN"


class AgentMessageTypes:
    """
    The possible values for the Agent message_type field. This consists
    of all the values defined in the class NotificationTypes plus the
    following values.
    """
    keep_alive = "KEEP_ALIVE"
    going_down = "GOING_DOWN"


class AgentFields:

    # Present in all message types
    hostname = 'hostname'
    timestamp = 'timestamp'
    message_type = 'type'

    # Only present if message_type is one of the values defined in the
    # NotificationTypes class.
    message = 'message'
    short_message = 'short_message'
    is_report = 'is_report'
    monitoring_module = 'monitoring_module'
    module_fields = 'module_fields'

    # Only present if the message_type is 'KEEP_ALIVE'
    command_port = 'command_port'

    # Only present if message_type is 'COMMAND_RESPONSE'
    command_id = 'command_id'
    command = 'command'
    command_response_fields = 'command_response_fields'

    # Optional: Only if authentication is enabled (for any message type)
    username = 'username'
    password = 'password'



class AgentCommandFields:
    """
    The fields for a command message that is send on the command port.
    * target: The target of the command. It can be a module name or 'GENERAL'
      for a general command.
    * command: The name of the command. It depends on the target. If the target
      is general it can have one of the following values:
      - "GET_CONFIGS": The Notifications Server requests the configurations of
        the agent.
      - "SET_CONFIGS": The Notifications Server requests setting the configs
        of the agent.
      - "RESTART": The Notifications Server request restarting the agent.
      - "CLOSE_CONNECTION": An request to close an existing connection.
    * command_id: An integer to match the response (if any) to the command.
      Should be -1 for asynchronous responses.
    * username: If agent authentication is enabled, the username of the agent.
    * password: If agent authentication is enabled, the password of the agent.
    * body: The actual body of the command (if needed). If it's not needed,
      it should be an empty dictionary.
    """
    target = 'target'
    command = 'command'
    command_id = 'command_id'
    username = 'username'
    password = 'password'
    body = 'body'


def load_modules_from_target(target, *module_args):
    """
    Target can have one of the following values:
    * agent
    * gui
    * server
    """
    # So we won't load the same module twice
    found_modules = []

    modules_objects = []

    relative_path = os.path.join(UMIT_NI_MODULES, target)
    # First try to load modules relative to the current directory if in sys.path
    if '.' in sys.path:
        load_modules_from_path(relative_path, found_modules,
                               modules_objects, *module_args)

    for base_path in sys.path:
        full_path = os.path.join(base_path, relative_path)
        load_modules_from_path(full_path, found_modules,
                               modules_objects, *module_args)

    return modules_objects


def load_modules_from_path(full_path, found_modules,
                           modules_objects, *module_args):
    # Get all module files in the directory 
    modules_paths = glob(os.path.join(full_path, '*.py'))

    for module_path in modules_paths:
        if module_path.endswith('__init__.py'):
            continue

        # Find out the module name
        module_name = os.path.split(module_path)[1]
        if module_name == '':
            continue

        # Ignore the .py extension
        module_name = module_name[:len(module_name) - 3]

        # If we already found this module
        if module_name in found_modules:
            continue

        # Try to load the found module
        try:
            module_obj = load_module(module_name, module_path, *module_args)
            modules_objects.append(module_obj)
            
            # Save the module name for the modules we found
            found_modules.append(module_name)
        except:
            logging.error('Failed loading module %s from %s',
                          module_name, module_path, exc_info=True)


def load_module(module_name, path, *module_args):
    """
    Loads a module with the given name from the given target.
    Target can have one of the following values:
    * agent
    * gui
    * server
    """
    logging.info('Trying to load module: %s', module_name)

    try:
        module_mod = imp.load_source(module_name, path)
    except:
        logging.error('Corrupt module:', exc_info=True)
        raise CorruptInventoryModule(module_name, path,
                CorruptInventoryModule.corrupt_path)

    # Try to get a reference to the class of this Module.
    try:
        mod_class = module_mod.__dict__[module_name]
    except:
        logging.error('Corrupt module:', exc_info=True)
        raise CorruptInventoryModule(module_name, path,
                CorruptInventoryModule.corrupt_file)

    # Return the initialized object
    return mod_class(*module_args)



class CorruptInventoryModule(Exception):
    """
    It is inherited by specific Exception classes for the Agent and Server
    modules.

    An exception generated when the module couldn't be loaded. Generic cases:
        corrupt_path: The file called [module_name].py couldn't be located at
                      the specified path.
        corrupt_file: The file [module_name].py was found at the specified
                      path, but it didn't contained a class called
                      [module_name].
        get_name:     The module doesn't implement the mandatory get_name()
                      method or it's result is incorrect.
    """

    corrupt_path = 0
    corrupt_file = 1

    def __init__(self, module_name, module_path, err_type=0):
        self.err_message = 'Module ' + str(module_name) + ':'
        if err_type == CorruptInventoryModule.corrupt_path:
            self.err_description = module_path + '/' + module_name + '.py ' +\
                    ' not found, missing permissions or invalid syntax'
        elif err_type == CorruptInventoryModule.corrupt_file:
            self.err_description = module_path + '/' + module_name + '.py ' +\
                    'doesn\'t contain a class called ' + module_name
        else:
            self.err_description = 'Undefined error'


    def __str__(self):
        return repr(self.err_message + self.err_description)
