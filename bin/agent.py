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
from umit.inventory import agent
from umit.inventory.agent import Configs
from umit.inventory.agent import Core

def main(args):
    """The Umit Agent main function"""

    # The Agent Configurations. See umit/inventory/agent/Configs.py
    # for details regarding the configuration file location and default
    # settings.
    configurations = Configs.AgentConfig()

    # The message Parser which will encrypt (if specified) and send the 
    # messages.
    parser = Core.AgentMessageParser(configurations)

    # The event-based main loop of the Agent.
    agent_main_loop = Core.AgentMainLoop(parser)
    agent_main_loop.run()


if __name__=="__main__":
    main(sys.argv)
