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
from collections import deque

from umit.inventory.agent import Core
from umit.inventory.agent.MonitoringModule import MonitoringModule
from umit.inventory.common import NotificationTypes


LINUX = sys.platform.lower().startswith('linux')
OSX = sys.platform.lower().startswith('darwin')
BSD = sys.platform.lower().startswith('freebsd')
POSIX = os.name == 'posix'
WIN = sys.platform.lower().startswith('win32')

if WIN:
    try:
        import win32api
        import wmi
        import win32file
    except:
        WIN = False


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


    def get_hdd_total_space(self):
        """
        Returns the total amount of HDD space in bytes.

        Availability: Windows
        """
        # Compute total space on
        if WIN:
            drives = win32api.GetLogicalDriveStrings()
            total_size = 0

            # Iterate over all the drives
            for drive in drives:
                # Only computing for HDD drives
                if win32file.GetDriveType(drive) == win32file.DRIVE_FIXED:
                    sizes = win32api.GetDiskFreeSpace(drive)
                    total_size += sizes[0] * sizes[1] * sizes[3]

            return total_size



class DeviceValueTracker:
    """
    Class to track a given device value (like recv_bytes/sec, cpu usage, etc).
    The value can be tracked in 2 modes:
        * the latest value recorded (eg: total bytes received)
        * the average of the value over a pariod of time (eg: bytes/sec)
    """

    def __init__(self, measurement_gen, average=False, time_interval_size=1.0):
        """
        measurement_gen: A MeasurementGenerator object.
        average: If the tracker should compute the average.
        time_interval_size: the time period over which the average should be
        computed. Only relevant if average is True.
        """
        self.measurement_gen = measurement_gen
        self.measurement_gen.register_tracker(self)
        self.average = average
        self.time_interval_size = time_interval_size

        if self.average:
            self.measurement_avg = MeasurementAverage(time_interval_size)
        else:
            self.instant_value = 0.0


    def get_value(self):
        """ Returns the latest value for this tracker (average or not) """
        latest_value = measurement_gen.get_latest_value()
        if latest_value != None:
            if self.average:
                self.measurement_avg.add_measurement(latest_value)
                return self.measurement_avg.get_average()
            else:
                self.instant_value = latest_value
                return self.instant_value



class MeasurementGenerator:
    """ An abstract class which does a measurement. """

    def __init__(self):
        self.trackers = dict()
        self.latest_value = 0.0


    def register_tracker(self, tracker):
        """
        DeviceValueTracker objects which use this object must register
        themselvs so they won't receive duplicate values with the
        get_latest_value() method.
        """
        self.trackers[tracker] = False


    def measure(self):
        """
        Does the actual measurement. Must be implemented and call this
        function first.
        """
        for tracker in self.trackers.keys():
            self.trackers[tracker] = False


    def get_latest_value(self, tracker=None):
        """
        Returns the latest measured value or None if the tracker was
        registered and it already requested this value.
        tracker: The tracker which requests the value. If it's None, then
        it won't check if it was already returned.
        """
        if tracker == None:
            return self.latest_value

        if tracker not in self.trackers.keys():
            return self.latest_value

        if self.trackers[tracker]
            return None
        return self.latest_value



# Measurement generators -- START

class UptimeGenerator:
    """
    Computes the number of seconds (floating point precision) of
    the device uptime.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = time.time() - self.get_boot_time()


class LoadAverage1Generator:
    """
    Computes the load average over the last minute.
    Availability: UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if not POSIX:
            self.latest_value = None
        self.latest_value = os.getloadavg[0]


class LoadAverage5Generator:
    """
    Computes the load average over the last 5 minutes.
    Availability: UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if not POSIX:
            self.latest_value = None
        self.latest_value = os.getloadavg[1]


class LoadAverage15Generator:
    """
    Computes the load average over the last 15 minutes.
    Availability: UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if not POSIX:
            self.latest_value = None
        self.latest_value = os.getloadavg[2]


class RamAvailableGenerator:
    """
    Computes the available RAM size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = psutil.avail_phymem()


class SwapAvailableGenerator:
    """
    Computes the available SWAP size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = psutil.avail_virtmem()


class SwapTotalGenerator:
    """
    Computes the total SWAP size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = total_virtmem()


class OpenPortsGenerator:
    """
    Computes the number of open UDP and TCP ports on the host.
    Warning: Requires super-user access rights.

    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)

        port_count = 0

        # Iterate over the processes and count how many ports each process
        # has opened
        processes = psutil.process_iter()
        for process in processes:
            try:
                port_count += len(process.get_connections())
            except:
                continue

        self.latest_value = port_count


class HostnameChangedGenerator:
    """
    Computes if the hostname was changed or not. The measure() method sets
    self.latest_value to True if the hostname was changed. False otherwise.
    Availability: Windows, UNIX
    """

    def __init__(self):
        MeasurementGenerator.__init__(self)
        self.initial_host_name = gethostname()

    def measure(self):
        MeasurementGenerator.measure(self)

        current_host_name = gethostname()
        if current_host_name == self.initial_host_name:
            self.latest_value = False
            return
        self.initial_host_name = current_host_name
        self.latest_value = True


# Measurement generators -- END



class MeasurementAverage:
    """
    Class optimised to compute the average of a measurement over a predefined
    period of time (which is given at construction). It holds an internal
    queue of the measurements so if the period of the time is bigger, so the
    size of the queue will grow.
    The expected average computation time is constant.
    The measurement must be an int or a float.
    """

    min_time_interval_size = 0.1

    def __init__(self, time_interval_size):
        """
        time_interval_size: A float representing the number of seconds for
        which the average of the measurements should be computed. It must
        be at least MeasurementAverage.min_time_interval_size.
        """
        if self.time_interval_size < MeasurementAverage.min_time_interval_size:
            raise TimeIntervalSizeTooLow(time_interval_size,\
                    MeasurementAverage.min_time_interval_size)

        self.queue = deque()
        self.measurements_sum = 0.0
        self.first_timestamp = 0.0
        self.last_timestamp = 0.0
        self.size = 0
        self.time_interval_size


    def add_measurement(self, measurement):
        """
        Adds a measurement to the queue.
        measurement: an int or float which represents the measurement.
        """
        # Only measuring int or floats
        if type(measurement) != float and type(measurement) != int:
            return

        # Also adding a timestamp to the measurement
        current_time = time.time()
        self.queue.append((measurement, current_time))

        self.size += 1
        self.measurement_sum += float(measurement)

        # Deleting measurements which are too old for this time interval
        # This can't empty the queue because of the minimum time interval size
        # requirement.
        while self.queue[0][1] + self.time_interval_size > current_time:
            self.popleft()
            self.size -= 1


    def get_average(self):
        """
        Returns the average of the measurements over the given time interval
        size at construction.
        """
        return self.measurement_sum/self.size



class TimeIntervalSizeTooLow(Exception):

    def __init__(self, time_interval, time_interval_min):
        self.err_msg = 'Minimum time interval supported: %s. Got: %s' %\
                (str(time_interval), str(time_interval_min))

    def __str__(self):
        return repr(self.err_msg)

