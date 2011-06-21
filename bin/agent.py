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
import traceback

import umit.inventory
from umit.inventory import agent
from umit.inventory.agent.Configs import AgentConfig
from umit.inventory.agent import Core
from umit.inventory.agent.Core import CorruptAgentModule


def main(args):
    """The Umit Agent main function"""


    # The Agent Configurations. See umit/inventory/agent/Configs.py
    # for details regarding the configuration file location and default
    # settings.
    conf = AgentConfig()

    # The message Parser which will encrypt (if specified) and send the 
    # messages.
    parser = Core.AgentNotificationParser(conf)

    # The event-based main loop of the Agent.
    agent_main_loop = Core.AgentMainLoop(parser, conf)

    """
    # Initialize the monitoring modules
    modules_names = conf.get_modules_list()
    modules = []
    for module_name in modules_names:
        if not conf.module_get_enable(module_name):
            continue
        try:
            module_path = conf.module_get_option(module_name,\
                    AgentConfig.module_path)
            module_obj = umit.inventory.common.load_module(module_name,\
                    module_path, conf, agent_main_loop)

            # Do a sanity check to test the module is correct
            try:
                module_name = module_obj.get_name()
            except:
                raise CorruptAgentModule(module_name, module_path,\
                        CorruptAgentModule.get_name)
            if module_name != module_obj.get_name():
                raise CorruptAgentModule(module_name, module_path,\
                        CorruptAgentModule.get_name)

        except Exception, e:
            traceback.print_exc()
            continue

        modules.append(module_obj)

    # Set the modules for the agent main loop
    agent_main_loop.modules = modules

    # Start the monitoring modules
    for module in modules:
        module.start()
    """
    # Start the main loop
    agent_main_loop.run()


if __name__=="__main__":
    main(sys.argv)

