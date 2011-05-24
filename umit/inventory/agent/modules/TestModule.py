#Copyright (C) 2011 Adriano Monteiro Marques.
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
from umit.inventory.common import NotificationTypes

class TestModule(MonitoringModule):

    # The name of the fields in the configuration file
    min_time_config = "MinTimeConfig"
    max_time_config = "MaxTimeConfig"
    message_size = "MessageSize"
    fields_num = "FieldsNumber"
    fields_length = "FieldsLength"


    def __init__(self, configs, agent_main_loop):
        MonitoringModule.__init__(self, configs, agent_main_loop)

        self.min_sleep_time = float(self.options[TestModule.min_time_config])
        self.max_sleep_time = float(self.options[TestModule.max_time_config])
        self.message_size = int(self.options[TestModule.message_size])
        self.fields_num = int(self.options[TestModule.fields_num])
        self.fields_length = int(self.options[TestModule.fields_length])


    def get_name(self):
        return 'TestModule'


    def _generate_random_message(self):
        # Waits a random time and generates a random message.
        temp = random() * (self.max_sleep_time - self.min_sleep_time)
        sleep_time = self.min_sleep_time = temp
        time.sleep(sleep_time)

        msg = ''
        for i in range(self.message_size):
            msg += choice(string.ascii_uppercase + string.digits)

        return msg


    def _generate_random_type(self):
        # Currently consider 12.5% chances to generate a CRITICAL notification.
        i = choice(range(8))
        if i == 0:
            return NotificationTypes.critical
        else:
            return NotificationTypes.info


    def _generate_random_fields(self):
        # Generate random fields with self.fields_num entries and each field
        # having exactly self.fields_length characters.
        fields = dict()
        for i in range(self.fields_num):
            field_name = "Field" + str(i)
            field_value = ''
            for j in range(self.fields_length):
                field_value += choice(string.ascii_uppercase)
            fields[field_name] = field_value

        return fields


    def run(self):

        while True:
            msg = self._generate_random_message()
            msg_type = self._generate_random_type()
            fields = self._generate_random_fields()

            self.send_message(msg, msg_type, fields)


    def init_default_settings(self):
        self.options[TestModule.min_time_config] = '0.0'
        self.options[TestModule.max_time_config] = '3.0'
        self.options[TestModule.message_size] = '50'
        self.options[TestModule.fields_num] = '3'
        self.options[TestModule.fields_length] = '15'


