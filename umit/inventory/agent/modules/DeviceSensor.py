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
import datetime
import psutil
from cStringIO import StringIO
from socket import gethostname
from collections import deque
from threading import Thread
from threading import Lock

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
        import pythoncom
    except:
        WIN = False


class DeviceSensor(MonitoringModule):

    # The name of the fields in the configuration file
    test_time = 'test_time'
    report_time = 'report_time'
    report_template_file = 'report_template_file'
    notification_cond_file = 'notification_cond_file'


    def __init__(self, configs, agent_main_loop):
        MonitoringModule.__init__(self, configs, agent_main_loop)

        # Get configurations
        self.test_time = float(self.options[DeviceSensor.test_time])
        self.report_time = float(self.options[DeviceSensor.report_time])
        self.report_template_file =\
                str(self.options[DeviceSensor.report_template_file])
        self.notification_cond_file =\
                str(self.options[DeviceSensor.notification_cond_file])

        self.measurement_manager = MeasurementManager()

        param = {'users' : ['root'], 'sort_by' : 'cpu', 'proc_no' : 10, 'sort_order': 'desc'}
        self._id = self.measurement_manager.add_variable('process_info', param)

    def get_name(self):
        return 'DeviceSensor'


    def run(self):
        report_time_count = 0.0

        while True:
            pre_measure_time = time.time()
            self.measure()

            # Count if we should send the report
            if report_time_count >= self.report_time:
                print self.measurement_manager.get_variable(self._id)
                report_time_count = 0.0
                self.report()

            # Making sure we aren't waiting useless time
            polling_step_time = time.time() - pre_measure_time
            if polling_step_time > self.test_time:
                continue

            time.sleep(self.test_time - polling_step_time)
            report_time_count += time.time() - pre_measure_time


    def init_default_settings(self):
        self.options[DeviceSensor.test_time] = '0.1'
        self.options[DeviceSensor.report_time] = '5'
        self.options[DeviceSensor.report_template_file] =\
                os.path.join('umit', 'inventory', 'agent', 'modules',\
                'device_sensor_report_template.txt')
        self.options[DeviceSensor.notification_cond_file] =\
                os.path.join('umit', 'inventory', 'agent', 'modules',\
                'device_sensor_notification_cond.txt')


    def measure(self):
        """ Called each self.test_time seconds to measure device info """
        self.measurement_manager.update()


    def report(self):
        """
        Called when the Device Sensor should send a report (as specified)
        with device information.
        """
        pass



class MeasurementManager:
    """
    Manages the measurement generators and the static measurements (like
    the ram total size). It holds a table of reference with associated
    names to the measurements which can be get with the get_measurement()
    function.

    Provided variables:
        * boot_time: Float representing the number of seconds since the
          epoch representing the time when the device booted.
        * hostname: The configured hostname.
        * boot_time_date: String representing the boot time above in the
          'Sun Jun 20 23:21:05 1993' form.
        * uptime: Float representing the device uptime in seconds.
        * process_info: String similar with the one provided by top which
          shows: USER, PID, %CPU, %MEM, VSZ, RSS, START, TIME and COMMAND.
        * load_avg1: Float representing the load average over the last
          minute (UNIX only).
        * load_avg5: Float representing the load average over the last
          5 minutes (UNIX only).
        * load_avg15: Float representing the load average over the last
          15 minutes (UNIX only).
        * ram_avail: Integer representing the number of available RAM bytes.
        * ram_used: Integer representing the number of used RAM bytes.
        * ram_total: Integer representing the number of total RAM bytes.
        * swap_avail: Integer representing the number of available SWAP bytes.
        * swap_used: Integer representing the number of used SWAP bytes.
        * swap_total: Integer representing the number of total SWAP bytes.
        * partition_avail: Integer representing the number of free bytes on a
          set of partitions.
        * open_ports: Integer representing the number of open TCP or UDP ports.
        * hostname_changed: Boolean which is true if the hostname was changed.
        * net_recv_bytes: Integer representing the number of received bytes.
        * net_sent_bytes: Integer representing the number of sent bytes.
        * net_total_bytes: Integer representing the sum of received and sent
          bytes.
        * net_recv_bps: Integer representing the number of received bytes
          per second.
        * net_sent_bps: Integer representing the number of sent bytes per
          second.
        * net_total_bps: Integer representing the sum of the received and
          sent bytes per second.
        * net_pack_recv: Integer representing the number of received packets.
        * net_pack_sent: Integer representing the number of sent packets.
        * net_pack_total: Integer representing the sum of received and sent
          packets.
        * ram_percent: Float representing division between ram_avail/ram_total.
        * cpu_percent: Float representing the system-wide cpu utilisation as a
          percentage.
        * partition_percent: Float representing the division between the free
          space on a set of partitions and the total space.

    """

    def __init__(self):

        # Initialise constant variables
        self.const_measurements = {\
                'boot_time' : self.get_boot_time,\
                'boot_time_data' : self.get_boot_time_date,\
                'ram_total' : self.get_ram_total,\
                'hostname' : self.get_hostname\
                }

        # Non-configurable measurement objects
        self.measurement_objects = {\
                'uptime' : UptimeGenerator(),\
                'load_avg1' : LoadAverage1Generator(),\
                'load_avg5' : LoadAverage5Generator(),\
                'load_avg15' : LoadAverage15Generator(),\
                'ram_avail' : RamAvailableGenerator(),\
                'ram_used' : RamUsedGenerator(),\
                'swap_avail' : SwapAvailableGenerator(),\
                'swap_total' : SwapTotalGenerator(),\
                'open_ports' : OpenPortsGenerator(),\
                'net_recv_bytes' : NetworkReceivedBytesGenerator(),\
                'net_sent_bytes' : NetworkSentBytesGenerator(),\
                'net_total_bytes' : NetworkTotalBytesGenerator(),\
                'net_recv_bps' : NetworkReceivedBpsGenerator(),\
                'net_sent_bps' : NetworkSentBpsGenerator(),\
                'net_total_bps' : NetworkTotalBpsGenerator(),\
                'net_pack_recv' : NetworkReceivedPacketsGenerator(),\
                'net_pack_sent' : NetworkSentPacketsGenerator(),\
                'net_pack_total' : NetworkTotalPacketsGenerator(),\
                'ram_percent' : RamPercentGenerator(),\
                'cpu_percent' : CpuPercentGenerator()\
                }

        # The classes for the configurable measurements
        self.conf_measurement_classes = {\
                'partition_avail' : PartitionAvailableGenerator,\
                'partition_percent' : PartitionPercentGenerator,\
                'process_info' : ProcessInfoGenerator\
                }

        # To save the parameters for the configurable measurements
        self.conf_measurement_ids = {}

        # The variables which should be measured
        self.measured_variables = {}

        # To add new configurable measurement variables in the
        # measured_variables dict
        self.measured_variables_last_id = 0


    def add_variable(self, var_name, var_param=None):
        """
        Adds a measurement for a device variable. Raises an
        InvalidVariableName exception if var_name isn't found.
        var_name: The name of the variable to be measured.
        var_param: If the variable is configurable, the parameters to
        configure it. This is a dictionary - 'param_name' : param_value.

        Returns: The ID for this measurement.
        """
        # Since is constant, the ID doesn't really matter
        if var_name in self.const_measurements.keys():
            return var_name

        # The variable is already measured, returning it's name
        if var_name in self.measured_variables.keys():
            return var_name

        # The variable isn't measured. Checking if it's non-configurable.
        if var_name in self.measurement_objects.keys():
            self.measured_variables[var_name] =\
                    self.measurement_objects[var_name]
            return var_name

        # If it's a configurable variable
        if var_name in self.conf_measurement_classes.keys():
            # Check if this configurable variable is already measured
            conf_measure_id = var_name + '::' + str(var_param)
            if conf_measure_id in self.conf_measurement_ids.keys():
                return self.conf_measurement_ids[conf_var_id]

            self.measured_variables_last_id += 1
            new_id = str(self.measured_variables_last_id)
            self.measured_variables[new_id] =\
                    self.conf_measurement_classes[var_name](var_param)
            self.conf_measurement_ids[conf_measure_id] = new_id
            return new_id

        raise InvalidVariableName(var_name)


    def update(self):
        """ Updates the variables with new measurements if required."""
        for measurement_gen in self.measured_variables.values():
            measurement_gen.measure()


    def get_variable(self, var_id):
        """
        Returns the latest value of a variable.
        var_id: The id of the variable, which is the variable name for the
        non-configurable variables and the value returned by
        add_configurable_variable() for configurable variables.
        """
        if var_id in self.const_measurements.keys():
            return self.const_measurements[var_id]()

        if var_id in self.measured_variables.keys():
            return self.measured_variables[var_id].get_latest_value()

        raise InvalidVariableName(var_id)


    @staticmethod
    def get_boot_time():
        return psutil.BOOT_TIME


    @staticmethod
    def get_boot_time_date():
        boot_time_struct = time.gmtime(psutil.BOOT_TIME)
        return time.asctime(boot_time_struct)


    @staticmethod
    def get_ram_total():
        return psutil.TOTAL_PHYMEM


    @staticmethod
    def get_hostname():
        return gethostname()



class DeviceValueTracker:
    """
    Class to track a given device value (like recv_bytes/sec, cpu usage, etc).
    The value can be tracked in 2 modes:
        * the latest value recorded (eg: total bytes received)
        * the average of the value over a pariod of time (eg: bytes/sec)
    """

    # Tracking types
    raw = 0
    average = 1
    differential = 2


    def __init__(self, measurement_gen, track_type=0, time_interval_size=1.0):
        """
        measurement_gen: A MeasurementGenerator object.
        track_type: If the tracker should compute the raw, average or
        differential value.
        time_interval_size: the time period over which the average should be
        computed. Only relevant if track_type is not DeviceValueTracker.raw.
        """
        self.measurement_gen = measurement_gen
        self.measurement_gen.register_tracker(self)
        self.latest_value = 0.0

        if track_type != DeviceValueTracker.raw:
            self.measurement_reducer = MeasurementReducer(time_interval_size)


    def get_value(self):
        """ Returns the latest value for this tracker (reduced or not) """
        latest_value = measurement_gen.get_latest_value()
        if latest_value != None:
            if track_type == DeviceValueTracker.average:
                self.measurement_reducer.add_measurement(latest_value)
                self.latest_value = self.measurement_reducer.get_average()

            if track_type == DeviceValueTracker.differential:
                self.measurement_reducer.add_measurement(latest_value)
                self.latest_value = self.measurement_reducer.get_differential()

            if track_type == DeviceValueTracker.raw:
                self.latest_value = latest_value

        return self.instant_value



class MeasurementGenerator:
    """ An abstract class which does a measurement. """

    def __init__(self, measurement_param={}):
        self.trackers = dict()
        self.latest_value = 0.0
        self.measurement_param = measurement_param


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

        if self.trackers[tracker]:
            return None
        return self.latest_value



# Measurement generators -- START

class UptimeGenerator(MeasurementGenerator):
    """
    Computes the number of seconds (floating point precision) of
    the device uptime.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = time.time() - self.get_boot_time()


class LoadAverage1Generator(MeasurementGenerator):
    """
    Computes the load average over the last minute.
    Availability: UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if not POSIX:
            self.latest_value = None
        self.latest_value = os.getloadavg[0]


class LoadAverage5Generator(MeasurementGenerator):
    """
    Computes the load average over the last 5 minutes.
    Availability: UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if not POSIX:
            self.latest_value = None
        self.latest_value = os.getloadavg[1]


class LoadAverage15Generator(MeasurementGenerator):
    """
    Computes the load average over the last 15 minutes.
    Availability: UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if not POSIX:
            self.latest_value = None
        self.latest_value = os.getloadavg[2]


class RamAvailableGenerator(MeasurementGenerator):
    """
    Computes the available RAM size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = psutil.avail_phymem()


class RamUsedGenerator(MeasurementGenerator):
    """
    Computes the used RAM size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = psutil.used_phymem()


class SwapAvailableGenerator(MeasurementGenerator):
    """
    Computes the available SWAP size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = psutil.avail_virtmem()


class SwapUsedGenerator(MeasurementGenerator):
    """
    Computes the used swap size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = psutil.used_virtmem()


class SwapTotalGenerator(MeasurementGenerator):
    """
    Computes the total SWAP size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = total_virtmem()


class OpenPortsGenerator(MeasurementGenerator):
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


class HostnameChangedGenerator(MeasurementGenerator):
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


class NetworkTrafficGenerator(MeasurementGenerator):
    """ Abstract class for generators which work with network traffic """

    def __init__(self):
        MeasurementGenerator.__init__(self)
        if LINUX:
            self.network_traffic = LinuxNetworkTraffic.get_instance()
        elif WIN:
            self.network_traffic = WindowsNetworkTraffic.get_instance()
        else:
            self.network_traffic = None


class NetworkReceivedBytesGenerator(NetworkTrafficGenerator):
    """
    Computes the received network bytes.
    Availability: Windows, Linux
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if network_traffic != None:
            self.latest_value = self.network_traffic.get_received_bytes()


class NetworkSentBytesGenerator(NetworkTrafficGenerator):
    """
    Computes the sent network bytes.
    Availability: Windows, Linux
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if network_traffic != None:
            self.latest_value = self.network_traffic.get_sent_bytes()


class NetworkTotalBytesGenerator(NetworkTrafficGenerator):
    """
    Computes the sum of send and received network bytes.
    Availability: Windows, Linux
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if network_traffic != None:
            self.latest_value = self.network_traffic.get_sent_bytes() + \
                    self.network_traffic.get_received_bytes()


class NetworkReceivedPacketsGenerator(NetworkTrafficGenerator):
    """
    Computes the number of received packets.
    Availability: Windows, Linux
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if network_traffic != None:
            self.latest_value = self.network_traffic.get_received_packets()


class NetworkSentPacketsGenerator(NetworkTrafficGenerator):
    """
    Computes the number of sent packets.
    Availability: Windows, Linux
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if network_traffic != None:
            self.latest_value = self.network_traffic.get_sent_packets()


class NetworkTotalPacketsGenerator(NetworkTrafficGenerator):
    """
    Computes the sum of received and sent packets.
    Availability: Windows, Linux
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if network_traffic != None:
            self.latest_value = self.network_traffic.get_sent_packets() +\
                    self.network_traffic.get_received_packets()


class NetworkTrafficPerSecGenerator(NetworkTrafficGenerator):
    """ Abstract class for counting per second traffic values """

    def __init__(self):
        NetworkTrafficGenerator.__init__(self)
        self.reducer = MeasurementReducer(1.0)

    def get_measured_traffic_value(self):
        # Must be implemented
        pass

    def measure(self):
        MeasurementGenerator.measure(self)
        if self.network_traffic != None:
            temp = self.get_measured_traffic_value()
            self.reducer.add_measurement(temp)
            self.latest_value = self.reducer.get_differential()


class NetworkReceivedBpsGenerator(NetworkTrafficPerSecGenerator):
    """
    Computes the number of received bytes over the last second from the
    time measure() is called.
    Availability: Windows, Linux
    """

    def get_measured_traffic_value(self):
        return self.network_traffic.get_received_bytes()


class NetworkSentBpsGenerator(NetworkTrafficGenerator):
    """
    Computes the number of sent bytes over the last second from the time
    measure() is called.
    Availability: Windows, Linux
    """

    def get_measured_traffic_value(self):
        return self.network_trafffic.get_sent_bytes()


class NetworkTotalBpsGenerator(NetworkTrafficGenerator):
    """
    Computes the sum between the sent and received bytes over the last second
    from the time measure() is called.
    Availability: Windows, Linux
    """

    def get_measured_traffic_value(self):
        return self.network_traffic.get_sent_bytes() +\
                self.network_traffic.get_total_bytes()


class RamPercentGenerator(MeasurementGenerator):
    """
    Computes the percent of how much the RAM is used.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        self.latest_value = float(psutil.used_phymem())/psutil.TOTAL_PHYMEM


class CpuPercentGenerator(MeasurementGenerator):
    """
    Computes the percent of how much the CPU is used.
    Availability: Windows, UNIX
    """

    def __init__(self):
        MeasurementGenerator.__init__(self)
        # First is measured with a 0.1 interval (according to psutil doc)
        self.latest_value = psutil.cpu_percent()

    def measure(self):
        MeasurementGenerator.measure(self)
        # Measuring with 0.0 interval, since we have over 0.1 seconds
        # between consecutive calls to cpu_percent()
        self.latest_value = psutil.cpu_percent(interval=0.0)


class PartitionAvailableGenerator(MeasurementGenerator):
    """
    Computes the total available number of bytes on the given list of partitions.
    For UNIX, the partition is given with it's mount point. For Windows, it's
    given by it's drive letter followed by a ':'.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if 'partitions' not in self.measurement_param.keys():
            return
        if WIN:
            self.measure_windows()
        if UNIX:
            self.measure_unix()

    def measure_unix():
        avail_size = 0
        try:
            for partition in self.measurement_param['partitions']:
                stat = os.statvfs(partition)
                avail_size += stat.f_frsize * stat.f_bavail
        except:
            pass
        self.latest_value = avail_size

    def measure_windows():
        avail_size = 0
        for partition in self.measurement_param['partitions']:
            sizes = win32api.GetDiskFreeSpace(partition)
            avail_size += sizes[0] * sizes[1] * sizes[2]
        self.latest_value = avail_size


class PartitionPercentGenerator(MeasurementGenerator):
    """
    Measures the percent of free space in the given partition list.
    Availability: Windows, UNIX
    """

    def measure(self):
        MeasurementGenerator.measure(self)
        if 'partitions' not in self.measurement_param.keys():
            return
        if UNIX:
            self.measure_unix()
        if WIN:
            self.measure_windows()

    def measure_unix(self):
        avail_size = 0
        total_size = 0
        for partition in self.measurement_param['partitions']:
            stat = os.statvfs(partition)
            avail_size += stat.f_bavail * stat.f_frsize
            total_size += stat.f_blocks * stat.f_frsize
        self.latest_value = float(avail_size)/total_size

    def measure_windows(self):
        avail_size = 0
        total_size = 0
        for partition in self.measurement_param['partitions']:
            sizes = win32api.GetDiskFreeSpace(partition)
            avail_size += sizes[0] * sizes[1] * sizes[2]
            total_size += sizes[0] * sizes[1] * sizes[3]
        self.latest_value = float(avail_size)/total_size



class ProcessInfoGenerator(MeasurementGenerator):
    """
    Generates information about the current processes.
    Availability: Windows, UNIX
    """

    def __init__(self, var_param):
        MeasurementGenerator.__init__(self, var_param)
        self.template = "%-9s %-5s %-4s %4s %7s %7s %5s %7s  %s"
        self.header = self.template % ("USER", "PID", "%CPU", "%MEM",\
                "VSZ", "RSS", "START", "TIME", "COMMAND")
        pid_list = psutil.get_pid_list()
        self.processes = {}
        for pid in pid_list:
            self.processes[pid] = psutil.Process(pid)
            self.processes[pid].get_cpu_percent(interval=0)


    def get_latest_value(self):
        self.measure(True)
        return self.latest_value


    def measure(self, full_measure=False):
        # full_measure is used to do the parsing only when requesting the value
        # since this MeasurementGenerator shouldn't be used for comparations.
        MeasurementGenerator.measure(self)

        # Find out new processes pid's
        current_pid_list = psutil.get_pid_list()
        old_pid_list = self.processes.keys()
        new_pid_list = [x for x in current_pid_list if not x in old_pid_list]

        # Delete dead processes
        for pid in old_pid_list:
            if pid not in current_pid_list:
                del self.processes[pid]

        for pid in new_pid_list:
            self.processes[pid] = psutil.Process(pid)
            # So the next measurements will be accurate
            self.processes[pid].get_cpu_percent(interval=0)

        if not full_measure:
            return

        processes_list = []
        today_day = datetime.date.today()
        for proc in self.processes.values():
            try:
                process_info = []
                user = proc.username
                if WIN and '\\' in user:
                    user = user.split('\\')[1]
                pid = proc.pid
                cpu = round(proc.get_cpu_percent(interval=0), 1)
                mem = round(proc.get_memory_percent(), 1)
                rss, vsz = [x/1024 for x in proc.get_memory_info()]

                start = datetime.datetime.fromtimestamp(proc.create_time)
                if start.date() == today_day:
                    start = start.strftime('%H:%M')
                else:
                    start = start.strftime('%b%d')

                cputime = time.strftime('%M:%S',\
                        time.localtime(sum(proc.get_cpu_times())))

                cmd = ' '.join(proc.cmdline)
                if not cmd:
                    cmd = '[%s]' % proc.name

                # Using a list instead of a dict here since this operation needs
                # to be finished fast.
                process_info.append(user)
                process_info.append(pid)
                process_info.append(cpu)
                process_info.append(mem)
                process_info.append(vsz)
                process_info.append(rss)
                process_info.append(start)
                process_info.append(cputime)
                process_info.append(cmd)
                processes_list.append(process_info)
            except:
                # The process died before we got to it in this loop
                del self.processes[proc.pid]
                pass

        # If we should keep only results from a list of users
        if 'users' in self.measurement_param.keys():
            users_list = self.measurement_param['users']
            new_process_list = []
            for proc in processes_list:
                if proc[0] in users_list:
                    new_process_list.append(proc)
            processes_list = new_process_list

        # If we should sort the data
        if 'sort_by' in self.measurement_param.keys():
            sort_criteria = self.measurement_param['sort_by']
            if 'sort_order' in self.measurement_param.keys() or\
                    self.measurement_param['sort_order'] == 'desc':
                sort_reversed = True
            else:
                sort_reversed = False
            if sort_criteria == 'cpu':
                processes_list.sort(ProcessInfoGenerator.sort_cpu,\
                        reverse=sort_reversed)
            if sort_criteria == 'ram':
                processes_list.sort(ProcessInfoGenerator.sort_ram,\
                        reverse=sort_reversed)

        # If we should keep only a part of the results
        if 'proc_no' in self.measurement_param.keys():
            proc_no = int(self.measurement_param['proc_no'])
            processes_list = processes_list[0:proc_no]

        # Format the data
        self.latest_value = self.header + '\n'
        for proc in processes_list:
            line = self.template % tuple(proc)
            self.latest_value += line + '\n'


    @staticmethod
    def sort_cpu(proc1, proc2):
        diff = proc1[2] - proc2[2]
        if diff < 0:
            return -1
        if diff > 0:
            return 1
        return 0


    @staticmethod
    def sort_ram(proc1, proc2):
        diff = proc1[3] - proc2[3]
        if diff < 0:
            return -1
        if diff > 0:
            return 1
        return 0

# Measurement generators -- END


class MeasurementReducer:
    """
    Class optimised to compute the average/differential of a measurement
    over a predefined period of time (which is given at construction).
    It holds an internal queue of the measurements so if the period of the
    time is bigger, so the size of the queue will grow.
    The expected reducing computation time is constant.
    The measurement must be an int or a float.
    """

    min_time_interval_size = 0.1

    def __init__(self, time_interval_size):
        """
        time_interval_size: A float representing the number of seconds for
        which the reducing of the measurements should be computed. It must
        be at least MeasurementReducer.min_time_interval_size.
        """
        if time_interval_size < MeasurementReducer.min_time_interval_size:
            raise TimeIntervalSizeTooLow(time_interval_size,\
                    MeasurementReducer.min_time_interval_size)

        self.queue = deque()
        self.measurements_sum = 0.0
        self.first_timestamp = 0.0
        self.last_timestamp = 0.0
        self.size = 0
        self.time_interval_size = time_interval_size


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
        self.measurements_sum += float(measurement)

        # Deleting measurements which are too old for this time interval
        # This can't empty the queue because of the minimum time interval size
        # requirement.
        while self.size > 0 and \
                self.queue[0][1] + self.time_interval_size < current_time:
            deleted_measurement = self.queue.popleft()
            self.size -= 1
            self.measurements_sum -= deleted_measurement[0]


    def get_average(self):
        """
        Returns the average of the measurements over the given time interval
        size at construction.
        """
        if self.size == 0:
            return 0.0
        return self.measurements_sum/self.size


    def get_differential(self):
        """
        Returns the difference between the first and last value in the queue.
        """
        queue_len = len(self.queue)
        if queue_len == 0:
            return 0.0
        return (self.queue[queue_len - 1][0] - self.queue[0][0])/\
                self.time_interval_size



class NetworkTraffic(Thread):
    """ Abstract class used to get network traffic info """

    # Singletone object
    instance = None

    def __init__(self):
        """ Shouldn't be used directly. Use get_instance() """
        Thread.__init__(self)
        self.traffic_lock = Lock()
        self.init_counters()


    def init_counters(self):
        self.received_bytes = 0
        self.sent_bytes = 0
        self.received_packets = 0
        self.sent_packets = 0


    def get_received_bytes(self):
        self.traffic_lock.acquire()
        temp = self.received_bytes
        self.traffic_lock.release()
        return temp


    def get_sent_bytes(self):
        self.traffic_lock.acquire()
        temp = self.sent_bytes
        self.traffic_lock.release()
        return temp


    def get_received_packets(self):
        self.traffic_lock.acquire()
        temp = self.received_packets
        self.traffic_lock.release()
        return temp


    def get_sent_packets(self):
        self.traffic_lock.acquire()
        temp = self.sent_packets
        self.traffic_lock.release()
        return temp


    def run(self):
        pass


class LinuxNetworkTraffic(NetworkTraffic):

    # Time between reading the information in seconds
    sleep_time = 0.2

    @staticmethod
    def get_instance():
        if NetworkTraffic.instance == None:
            NetworkTraffic.instance = LinuxNetworkTraffic()
            NetworkTraffic.instance.start()
        return NetworkTraffic.instance


    def run(self):
        while True:
            try:
                self.measure_traffic()
            except:
                pass
            time.sleep(LinuxNetworkTraffic.sleep_time)


    def measure_traffic(self):
        try:
            traffic_file = open('/proc/net/dev')
        except:
            return
        traffic_file_lines = traffic_file.readlines()

        self.traffic_lock.acquire()
        self.init_counters()

        # Ignoring first 2 lines
        for line in traffic_file_lines[2:]:
            line_info = line.split()

            try:
                self.received_bytes += int(line_info[1])
                self.received_packets += int(line_info[2])
                self.sent_bytes += int(line_info[9])
                self.sent_packets += int(line_info[10])
            except:
                self.traffic_lock.release()
                self.init_counters()
                return

        self.traffic_lock.release()



class WindowsNetworkTraffic(NetworkTraffic):

    @staticmethod
    def get_instance():
        if NetworkTraffic.instance == None:
            NetworkTraffic.instance = WindowsNetworkTraffic()
            NetworkTraffic.instance.start()
        return NetworkTraffic.instance


    def run(self):
        pythoncom.CoInitialize()
        _wmi = wmi.WMI()

        while True:
            recv_b_temp = 0
            sent_b_temp = 0
            recv_p_temp = 0
            sent_p_temp = 0
            interfaces = _wmi.Win32_PerfRawData_Tcpip_NetworkInterface()
            for interface in interfaces:
                recv_b_temp += int(interface.BytesReceivedPerSec)
                sent_b_temp += int(interface.BytesSentPerSec)
                recv_p_temp += int(interface.PacketsReceivedPerSec)
                sent_p_temp += int(interface.PacketsSentPerSec)

            self.traffic_lock.acquire()
            self.received_bytes = recv_b_temp
            self.sent_bytes = sent_b_temp
            self.received_packets = recv_p_temp
            self.sent_packets = sent_p_temp
            self.traffic_lock.release()
        pythoncom.CoUnitialize()



class TimeIntervalSizeTooLow(Exception):

    def __init__(self, time_interval, time_interval_min):
        self.err_msg = 'Minimum time interval supported: %s. Got: %s' %\
                (str(time_interval), str(time_interval_min))

    def __str__(self):
        return repr(self.err_msg)


class InvalidVariableName(Exception):

    def __init__(self, var_name):
        self.err_msg = 'Variable %s doesn\'t exist' % str(var_name)

    def __str__(self):
        return repr(self.err_msg)
