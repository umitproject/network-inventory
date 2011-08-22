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
import time
import os
import random

log_level_dict = {'warning' : logging.WARNING,
                  'info' : logging.INFO,
                  'critical' : logging.CRITICAL,
                  'debug' : logging.DEBUG,
                  'error' : logging.ERROR,
                  }

from umit.inventory.Configuration import InventoryConfig

def init_logger(configs, log_level=None, log_to_console=False):
    """
    configs: An InventoryConfig object which is used to determine the log path.
    l: The log level. See logging module.
    """
    try:
        log_path = str(configs.get(InventoryConfig.general_section,
                InventoryConfig.log_path))

        if log_level is None:
            l = configs.get(InventoryConfig.general_section,
                            InventoryConfig.log_level)
        else:
            l = log_level

        try:
            l = log_level_dict[l]
        except:
            l = logging.WARNING
    except:
        import traceback
        traceback.print_exc()
        # TODO decide if there is a better way to handle this
        return

    # Ensure the directory path exists
    try:
        os.makedirs(log_path)
    except:
        # We may get here if the path already exists. Checking later
        # if the path is valid.
        pass

    # Files are named by the time the process started + a random salt
    f_name = str(int(time.time())) + str(int(random.random() * 10000)) + '.log'
    full_path = os.path.join(log_path, f_name)

    # Config the logger with the file handler
    fh = logging.FileHandler(full_path, mode='w')
    formatter = logging.Formatter(get_format(l))
    fh.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(fh)
    logger.setLevel(l)

    # If configured, also log to console
    if log_to_console:
        ch = logging.StreamHandler()
        formatter = logging.Formatter(get_format(l))
        ch.setFormatter(formatter)
        logger = logging.getLogger()
        logger.addHandler(ch)


def get_format(level):
    time_sect = '[%(asctime)s]'
    level_sect = '[%(levelname)s]'
    thread_sect = '[%(threadName)s]'
    func_sect = '[%(pathname)s:%(funcName)s:%(lineno)d]'

    format = '---------------------------------\n'
    format += time_sect + level_sect
    if level == logging.DEBUG:
        format += thread_sect + func_sect

    format += '\n%(message)s'
    return format