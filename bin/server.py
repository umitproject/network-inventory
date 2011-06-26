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

from umit.inventory.server.Configs import ServerConfig
from umit.inventory.server.Core import ServerCore
from umit.inventory import Logger


def main(args):
    """The Umit Notifications Server  main function"""

    # The Server Configurations. See umit/inventory/agent/Configs.py
    # for details regarding the configuration file location and default
    # settings
    conf = ServerConfig()

    # Init the logging
    Logger.init_logger(conf, logging.DEBUG, True)

    # Load the Core based on the configs.
    core = ServerCore(conf)

    # Run the Core.
    core.run()


if __name__=="__main__":
    main(sys.argv)
