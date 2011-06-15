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

import os
import sys
import time
import psutil
from cStringIO import StringIO
from socket import gethostname

from umit.inventory.agent import Core
from umit.inventory.agent.MonitoringModule import MonitoringModule
from umit.inventory.common import NotificationTypes


WINDOWS = False
POSIX = False
if os.name == 'nt':
    WINDOWS = True
else:
    POSIX = True


class DeviceSensor(MonitoringModule):

    # The name of the fields in the configuration file
    test_time = 'test_time'
    report_time = 'report_time'


    def __init__(self, configs, agent_main_loop):
        MonitoringModule.__init__(self, configs, agent_main_loop)

        # Store initial host name to detect a change
        self.initial_host_name = gethostname()

        # Get configurations
        self.test_time = float(self.options[DeviceSensor.test_time])
        self.report_time = float(self.options[DeviceSensor.report_time])


    def get_name(self):
        return 'DeviceSensor'


    def run(self):
        report_time_count = 0.0

        while True:
            self.measure()

            # Count if we should send the report
            report_time_count += self.test_time
            if report_time_count >= self.report_time:
                report_time_count = 0.0
                self.report()

            time.sleep(self.test_time)


    def init_default_settings(self):
        self.options[DeviceSensor.test_time] = '0.1'
        self.options[DeviceSensor.report_time] = '300'


    def measure(self):
        """ Called each self.test_time seconds to measure device info """
        print 'Measuring ...'
        uptime = self.get_uptime()


    def report(self):
        """
        Called when the Device Sensor should send a report (as specified)
        with device information.
        """
        print 'Sending report ...'
        pass


    # Measurement functions

    def get_uptime(self):
        """
        Returns the number of seconds (floating point precission) of the
        device uptime.

        Availability: Windows, UNIX
        """
        return time.time() - self.get_boot_time()


    def get_boot_time(self):
        """
        Returns the boot time of the device measured in seconds since
        the epoch.

        Availability: Windows, UNIX
        """
        return psutil.BOOT_TIME


    def get_boot_time_string(self):
        """
        Returns a string with the form 'Sun Jun 20 23:21:05 1993' representing
        the boot time of the device.

        Availability: Windows, UNIX
        """
        boot_time_struct = time.gmtime(self.get_boot_time())
        return time.asctime(boot_time_struct)


    def get_load_average(self):
        """
        Returns a tuple representing the load average over the last
        1, 5 and 15 minutes.

        Availability: UNIX
        """
        if not POSIX:
            return None

        return os.getloadavg()


    def get_process_info(self):
        """
        Returns output similar to a top snapshot, showing the following
        information per-process: user, pid, cpu percentage, mem percentage,
        vsz, rss, start time, time running, command.

        Availability: Windows, UNIX
        """
        # Redirecting stdout since psutil.test() prints to stdout
        stdout_backup = sys.stdout
        str_output = StringIO()
        sys.stdout = str_output
        psutil.test()

        sys.stdout = stdout_backup
        return str_output.getvalue()


    def get_ram_total_size(self):
        """
        Returns the total size of the RAM.

        Availability: Windows, UNIX
        """
        return psutil.TOTAL_PHYMEM


    def get_ram_avail_size(self):
        """
        Return the size of available RAM.

        Availability: Windows, UNIX
        """
        return psutil.avail_phymem()


    def get_ram_used_size(self):
        """
        Returns the size of used RAM.

        Availability: Windows, UNIX
        """
        return psutil.used_phymem()


    def get_swap_total_size(self):
        """
        Returns the total size of the swap space.

        Availability: Windows, UNIX
        """
        return psutil.total_virtmem()


    def get_swap_avail_size(self):
        """
        Returns the available swap size.

        Availability: Windows, UNIX
        """
        return psutil.avail_virtmem()


    def get_swap_used_size(self):
        """
        Returns the used swap size.

        Availability: Windows, UNIX
        """
        return psutil.used_virtmem()


    def get_open_ports(self):
        """
        Returns the number of open UDP and TCP ports on the host.
        Warning: Requries super-used access rights.

        Availability: Windows, UNIX
        """
        port_count = 0

        # Iterate over the processes and count how many ports each process
        # has opened
        processes = psutil.process_iter()
        for process in processes:
            try:
                port_count += len(process.get_connections())
            except:
                continue

        return port_count


    def hostname_changed(self):
        """
        Returns True if a hostname change was detected since the last call
        (the difference between the calls being self.test_time).

        Availability: Windows, UNIX
        """
        current_host_name = gethostname()
        if current_host_name == self.initial_host_name:
            return False
        return True

