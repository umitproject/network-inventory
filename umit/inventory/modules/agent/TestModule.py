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
import threading
import logging

from umit.inventory.agent.MonitoringModule import MonitoringModule
from umit.inventory.common import NotificationTypes
from umit.inventory.Configuration import InventoryConfig


class TestModule(MonitoringModule):

    # Deactivated polling time (time between checking if it got activated)
    deactivated_polling_time = 5.0
    
    # The name of the fields in the configuration file
    min_time_config = "min_time"
    max_time_config = "max_time"
    message_size = "message_size"
    fields_num = "fields_number"
    fields_length = "fields_length"


    def __init__(self, configs, agent_main_loop):
        MonitoringModule.__init__(self, configs, agent_main_loop)

        self.min_sleep_time = float(self.options[TestModule.min_time_config])
        self.max_sleep_time = float(self.options[TestModule.max_time_config])
        self.message_size = int(self.options[TestModule.message_size])
        self.fields_num = int(self.options[TestModule.fields_num])
        self.fields_length = int(self.options[TestModule.fields_length])

        # Shutdown bool value and lock for it's access
        self.should_shutdown = False
        self.shutdown_lock = threading.Lock()

        self.activated = False
        self.activated_lock = threading.Lock()

    def get_name(self):
        return 'TestModule'


    def get_prefix(self):
        return 'test_module'


    def activate(self):
        self.activated_lock.acquire()
        self.activated = True
        self.activated_lock.release()


    def deactivate(self):
        self.activated_lock.acquire()
        self.activated = False
        self.activated_lock.release()

        
    def _generate_random_message(self):
        # Waits a random time and generates a random message.
        temp = random() * (self.max_sleep_time - self.min_sleep_time)
        sleep_time = self.min_sleep_time + temp
        time.sleep(sleep_time)

        msg = ''
        for i in range(self.message_size):
            msg += choice(string.ascii_uppercase + string.digits)

        return msg


    def _generate_random_type(self):
        # Currently consider 12.5% chances to generate a CRITICAL notification.
        i = choice(range(5))
        if i is 0:
            return NotificationTypes.critical
        elif i is 1:
            return NotificationTypes.warning
        elif i is 2:
            return NotificationTypes.security
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
        logging.info('Starting up the %s module ...', self.get_name())
        while True:
            self.activated_lock.acquire()
            if not self.activated:
                self.activated_lock.release()
                time.sleep(self.deactivated_polling_time)
                continue
            self.activated_lock.release()
            
            msg = self._generate_random_message()
            short_msg = 'Random message generated at %f' % time.time()
            msg_type = self._generate_random_type()
            fields = self._generate_random_fields()
            self.send_message(msg, short_msg, msg_type, fields, False)


    def init_default_settings(self):
        self.options[TestModule.min_time_config] = '0.0'
        self.options[TestModule.max_time_config] = '3.0'
        self.options[TestModule.message_size] = '50'
        self.options[TestModule.fields_num] = '3'
        self.options[TestModule.fields_length] = '15'
        self.options[InventoryConfig.module_enabled] = False