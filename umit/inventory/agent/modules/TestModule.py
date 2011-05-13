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

from random import random
from random import choice
import string
import time

from umit.inventory.agent import Core
from umit.inventory.agent.MonitoringModule import MonitoringModule
from umit.inventory.common import MessageTypes

class TestModule(MonitoringModule):

    # The name of the fields in the configuration file
    min_time_config = "MinTimeConfig"
    max_time_config = "MaxTimeConfig"
    message_size = "MessageSize"


    def __init__(self, configs, agent_main_loop):
        MonitoringModule.__init__(self, configs, agent_main_loop)

        self.min_sleep_time = self.options[TestModule.min_time_config]
        self.max_sleep_time = self.options[TestModule.max_time_config]
        self.message_size = self.options[TestModule.message_size]


    def get_name(self):
        return "TestModule"


    def generate_random_message(self):
        """ Waits a random time and generates a random message"""
        temp = random() * (self.max_sleep_time - self.min_sleep_time)
        sleep_time = self.min_sleep_time = temp
        time.sleep(sleep_time)

        msg = ''
        for i in range(self.message_size):
            msg += choice(string.ascii_uppercase + string.digits)

        return msg


    def start(self):

        while True:
            msg = self.generate_random_message()
            self.send_message(msg)


    def get_default_settings(self):
        settings = dict()
        settings[TestModule.min_time_config] = '0.0'
        settings[TestModule.max_time_config] = '5.0'
        settings[TestModule.message_size] = '100'

        return settings


