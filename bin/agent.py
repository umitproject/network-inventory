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
import logging

from umit.inventory.agent.Configs import AgentConfig
from umit.inventory.agent import Core
from umit.inventory import Logger

def main(args):
    """The Umit Agent main function"""


    # The Agent Configurations. See umit/inventory/agent/Configs.py
    # for details regarding the configuration file location and default
    # settings.
    conf = AgentConfig()

    # Init the logging
    Logger.init_logger(conf, True)

    # The message Parser which will encrypt (if specified) and send the 
    # messages.
    parser = Core.AgentNotificationParser(conf)

    # The event-based main loop of the Agent.
    agent_main_loop = Core.AgentMainLoop(parser, conf)

    # Start the main loop
    agent_main_loop.run()


if __name__=="__main__":
    main(sys.argv)

