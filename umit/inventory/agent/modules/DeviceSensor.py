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
import string
import datetime
import json
import re
import psutil
import logging
from socket import gethostname
from collections import deque
from threading import Thread
from threading import Lock

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
    reporting_enabled = 'reporting_enabled'
    

    # Module fields
    uptime = 'uptime'
    cpu_percent = 'cpu_percent'
    ram_percent = 'ram_percent'
    boot_time = 'boot_time_date'
    net_sent_bytes = 'net_sent_bytes'
    net_recv_bytes = 'net_recv_bytes'


    def __init__(self, configs, agent_main_loop):
        MonitoringModule.__init__(self, configs, agent_main_loop)

        # Get configurations
        self.test_time = float(self.options[DeviceSensor.test_time])
        self.report_time = float(self.options[DeviceSensor.report_time])
        self.report_template_file =\
                str(self.options[DeviceSensor.report_template_file])
        self.notification_cond_file =\
                str(self.options[DeviceSensor.notification_cond_file])
        self.reporting_enabled = \
                bool(self.options[DeviceSensor.reporting_enabled])
        
        self.measurement_manager = MeasurementManager()
        self.trackers_manager = TrackersManager(self.notification_cond_file, self)
        if self.reporting_enabled:
            self.trackers_manager.parse_report_file(self.report_template_file,\
                    self.report_time)


    def get_name(self):
        return 'DeviceSensor'


    def get_prefix(self):
        return 'device_sensor'


    def run(self):
        logging.info('Starting up the %s module ...', self.get_name())
        while True:
            
            pre_update_time = time.time()
            self.update()
            post_update_time = time.time()
            diff_time = post_update_time - pre_update_time
            if diff_time >= self.test_time:
                continue
            time.sleep(self.test_time - diff_time)


    def init_default_settings(self):
        self.options[DeviceSensor.test_time] = '0.25'
        self.options[DeviceSensor.report_time] = '10'
        self.options[DeviceSensor.report_template_file] =\
                os.path.join('umit', 'inventory', 'agent', 'modules',\
                'device_sensor_report_template.txt')
        self.options[DeviceSensor.notification_cond_file] =\
                os.path.join('umit', 'inventory', 'agent', 'modules',\
                'device_sensor_notification_cond.txt')
        self.options[DeviceSensor.reporting_enabled] = False


    def update(self):
        """ Called each self.test_time seconds to measure device info """
        self.measurement_manager.update()
        self.trackers_manager.update()



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

        logging.info('Initialized the DeviceSensor MeasurementManager')


    def add_measurement(self, var_name, var_param=None):
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
            logging.debug('Asking measurement for constant variable %s',\
                          var_name)
            return var_name

        # The variable is already measured, returning it's name
        if var_name in self.measured_variables.keys():
            logging.debug('Already measured variable id %s', var_name)
            return var_name

        # The variable isn't measured. Checking if it's non-configurable.
        if var_name in self.measurement_objects.keys():
            self.measured_variables[var_name] =\
                    self.measurement_objects[var_name]
            logging.debug('Adding measurement for variable %s', var_name)
            return var_name

        # If it's a configurable variable
        if var_name in self.conf_measurement_classes.keys():
            # Check if this configurable variable is already measured
            conf_measure_id = var_name + '::' + str(var_param)
            
            if conf_measure_id in self.conf_measurement_ids.keys():
                logging.debug('Already measured variable id %s', var_name)
                return self.conf_measurement_ids[conf_measure_id]

            self.measured_variables_last_id += 1
            new_id = str(self.measured_variables_last_id)

            self.measured_variables[new_id] =\
                    self.conf_measurement_classes[var_name](var_param)
            self.conf_measurement_ids[conf_measure_id] = new_id
            logging.debug('Adding measurement for variable %s with id %s',\
                          var_name, new_id)
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



class TrackerDefinitionFields:
    """
    The fields which are found in the tracker definitions file for a given
    tracker.
    var_name: The name of the variable to be tracked.
    var_param: Variable parameters if it has any.
    threshold: The accepted limit for this variable.
    threshold_comp: The comparation mode with the threshold.
    mode: The mode of the tracking: raw, avg or diff.
    reducing_time: If mode is avg or diff, the time interval for the reduction.
    notif_type: The type of the notification to be sent.
    notif_short_msg: Very short description of the notification.
    notif_msg: The message to be sent alongside the notification.
    """
    var_name = 'tracking_variable'
    var_param = 'tracking_variable_param'
    threshold = 'threshold'
    threshold_comp = 'threshold_comp'
    mode = 'mode'
    reducing_time = 'reducing_time'
    notif_short_msg = 'notif_short_msg'
    notif_msg = 'notif_msg'
    notif_type = 'notif_type'
    cooldown = 'cooldown'


class TrackersManager:

    def __init__(self, trackers_file, device_sensor):
        self.device_sensor = device_sensor
        self.measurement_manager = device_sensor.measurement_manager
        self.trackers = []
        self._parse_conditions(trackers_file)

        # Add measurements for variables we will send in the
        self.measurement_manager.add_measurement(DeviceSensor.uptime)
        self.measurement_manager.add_measurement(DeviceSensor.cpu_percent)
        self.measurement_manager.add_measurement(DeviceSensor.ram_percent)
        self.measurement_manager.add_measurement(DeviceSensor.net_sent_bytes)
        self.measurement_manager.add_measurement(DeviceSensor.net_recv_bytes)

        logging.info('Initialized DeviceSensor TrackersManager')


    def update(self):
        """ Forces all the trackers to check their value """
        for tracker in self.trackers:
            tracker.check_value()


    def _parse_conditions(self, trackers_file):
        # Parses the conditions defined in the trackers file and starts
        # the trackers
        try:
            f = open(trackers_file)
        except:
            logging.error('Could not open DeviceSensor trackers file at %s',\
                          trackers_file)
            return
        trackers_file_content = f.read()
        try:
            file_trackers_list = json.loads(trackers_file_content)
        except:
            error_str = 'Could not load DeviceSensor trackers file at %s.\n'
            error_str += 'Make sure it is JSON seriazable.'
            logging.error(error_str, trackers_file)
            return

        try:
            for tracker_definition in file_trackers_list:
                tracker = self._tracker_from_definition(tracker_definition)
                if tracker is not None:
                    self.trackers.append(tracker)
        except:
            error_str = 'Failed loading DeviceSensor trackers from file at %s.'
            logging.error(error_str, trackers_file, exc_info=True)


    def parse_report_file(self, report_file, report_cooldown):
        """ Parses the report file template and adds a special tracker """
        try:
            f = open(report_file)
        except:
            error_str = 'Failed opening DeviceSensor report template at %s'
            logging.error(error_str, report_file)
            return
        report_template = f.read()
        tracker_def = dict()

        tracker_def[TrackerDefinitionFields.var_name] = None
        tracker_def[TrackerDefinitionFields.var_param] = None
        # Next 2 definitions are to force the ramp-up
        tracker_def[TrackerDefinitionFields.mode] = 'average'
        tracker_def[TrackerDefinitionFields.reducing_time] = report_cooldown
        tracker_def[TrackerDefinitionFields.threshold] = None
        tracker_def[TrackerDefinitionFields.threshold_comp] = None
        tracker_def[TrackerDefinitionFields.cooldown] = report_cooldown
        tracker_def[TrackerDefinitionFields.notif_short_msg] =\
            'Scheduled Device Sensor report (each %.2f minutes)' %\
            (report_cooldown/60.0)
        tracker_def[TrackerDefinitionFields.notif_msg] = report_template
        tracker_def[TrackerDefinitionFields.notif_type] =\
                NotificationTypes.info

        try:
            tracker = self._tracker_from_definition(tracker_def, True)
            self.trackers.append(tracker)
        except:
            error_str = 'Failed loading DeviceSensor template defined at %s'
            logging.error(error_str, report_file, exc_info=True)


    def _tracker_from_definition(self, tracker_def, report_tracker=False):
        keys = tracker_def.keys()

        # Grab the fields in the definition
        var_name = tracker_def[TrackerDefinitionFields.var_name]
        if TrackerDefinitionFields.var_param in keys:
            var_param = tracker_def[TrackerDefinitionFields.var_param]
        else:
            var_param = {}
        if TrackerDefinitionFields.mode in keys:
            mode = tracker_def[TrackerDefinitionFields.mode]
        else:
            mode = 'raw'
        if mode != 'raw' and TrackerDefinitionFields.reducing_time not in keys:
            return None
        if TrackerDefinitionFields.reducing_time in keys:
            reducing_time = tracker_def[TrackerDefinitionFields.reducing_time]
            reducing_time = float(reducing_time)
        else:
            reducing_time = 0.0
        if TrackerDefinitionFields.cooldown in keys:
            cooldown = tracker_def[TrackerDefinitionFields.cooldown]
        else:
            cooldown = 360.0
        notif_msg = tracker_def[TrackerDefinitionFields.notif_msg]
        short_notif_msg = tracker_def[TrackerDefinitionFields.notif_short_msg]
        notif_type = tracker_def[TrackerDefinitionFields.notif_type]
        threshold = tracker_def[TrackerDefinitionFields.threshold]
        threshold_comp = tracker_def[TrackerDefinitionFields.threshold_comp]

        threshold = self.multiply_with_modifier(threshold)
        if threshold is None and not report_tracker:
            return None

        notif_msg, notif_vars, notif_vars_modifiers =\
                self.parse_message_template(notif_msg)

        if not report_tracker:
            var_id = self.measurement_manager.add_measurement(var_name,\
                    var_param)
        else:
            var_id = None

        # Special case in each we want a ReportTracker
        if report_tracker:
            tracker_class = ReportTracker
        else:
            tracker_class = DeviceValueTracker

        # Log the tracker
        if not report_tracker:
            info_str = 'Loaded tracker with definition:\n'
            info_str += json.dumps(tracker_def, sort_keys=True, indent=4)
            info_str += '\nPre-formated body:\n'
            info_str += notif_msg
            logging.info(info_str)
        else:
            info_str = 'Loaded report with the following pre-formated body:\n'
            info_str += notif_msg
            info_str += '\nReporting each %f seconds' % cooldown
            logging.info(info_str)

        # Return the initialized tracker
        return tracker_class(self.measurement_manager, var_id, threshold,\
                threshold_comp, notif_msg, short_notif_msg, notif_type,\
                notif_vars, notif_vars_modifiers, self, cooldown, mode,\
                reducing_time)


    def parse_message_template(self, notif_msg):
        notif_vars = []
        notif_vars_modifiers = []

        # Get the variables and add measurements to them
        var_re = re.compile('\$\([^$(]*\)')
        variables = var_re.findall(notif_msg)
        for var in variables:
            var = var.strip('$()')
            var_elements = var.split()
            var_name = var_elements[0]
            var_param = {}
            for var_param_attribution in var_elements[1:]:
                temp = var_param_attribution.split('=')
                var_param_left = temp[0]
                var_param_right = temp[1]
                # In case we have a list
                try:
                    var_param_right = json.loads(var_param_right)
                except:
                    pass
                var_param[var_param_left] = var_param_right

            if 'modifier' in var_param.keys():
                modifier = self.get_modifier(var_param['modifier'])
                notif_vars_modifiers.append(modifier)
            else:
                notif_vars_modifiers.append(None)

            # Add a measurement for each variable found here. 'threshold' and
            # 'value' are special cases which belong to the tracker.
            if var_name == 'threshold' or var_name == 'value':
                notif_vars.append(var_name)
                continue
            vid = self.measurement_manager.add_measurement(var_name, var_param)
            notif_vars.append(vid)

        # Replace the variables with the %s string
        variables_iter = var_re.finditer(notif_msg)
        prev_stop = -1
        new_notif_msg = ''
        for var_pos in variables_iter:
            var_start, var_stop = var_pos.span()
            new_notif_msg += notif_msg[prev_stop + 1:var_start]
            new_notif_msg += '%s'
            prev_stop = var_stop
        new_notif_msg += notif_msg[prev_stop + 1:len(notif_msg)]

        return new_notif_msg, notif_vars, notif_vars_modifiers


    @staticmethod
    def multiply_with_modifier(threshold):
        if type(threshold) == float or type(threshold) == int:
            return threshold
        if type(threshold) != str:
            return None
        threshold = threshold.strip()
        l = len(threshold)
        modifier = TrackersManager.get_modifier(threshold)
        if modifier is not None:
            return float(threshold[:l-2] * modifier)
        return float(threshold)


    @staticmethod
    def get_modifier(value):
        _value = str(value)
        l = len(_value)
        modifier = string.lower(_value[l-2:l])
        if modifier == 'kb':
            return 2**10
        if modifier == 'mb':
            return 2**20
        if modifier == 'gb':
            return 2**30
        if modifier == 'tb':
            return 2**40
        return None


    def alert(self, msg, msg_type, short_msg, is_report):
        fields = dict()
        fields[DeviceSensor.uptime] =\
                self.measurement_manager.get_variable(DeviceSensor.uptime)
        fields[DeviceSensor.cpu_percent] =\
                self.measurement_manager.get_variable(DeviceSensor.cpu_percent)
        fields[DeviceSensor.ram_percent] = \
                self.measurement_manager.get_variable(DeviceSensor.ram_percent)
        fields[DeviceSensor.net_sent_bytes] =\
                self.measurement_manager.get_variable(DeviceSensor.net_sent_bytes)
        fields[DeviceSensor.net_recv_bytes] =\
                self.measurement_manager.get_variable(DeviceSensor.net_recv_bytes)

        self.device_sensor.send_message(msg, short_msg, msg_type,\
                                        fields, is_report)



class DeviceValueTracker:
    """
    Class to track a given device value (like recv_bytes/sec, cpu usage, etc).
    The value can be tracked in 2 modes:
        * the latest value recorded (eg: total bytes received)
        * the average of the value over a pariod of time (eg: bytes/sec)
    """

    # Tracking types
    raw = 'raw'
    average = 'average'
    differential = 'differential'

    # Threshold compare mode
    greater = 'gt'
    greater_equal = 'gte'
    equal = 'eq'
    less_equal = 'lte'
    less = 'less'


    def __init__(self, measure_manager, varid, threshold, comp_mode, notif_msg,\
            short_notif_msg, notif_type, notif_vars, notif_vars_modifiers,\
            tracker_manager, cooldown=300.0, track_type='raw',\
            time_interval_size=1.0):
        """
        measure_manager: A MeasurementManager object.
        varid: The variable id of the variable we are tracking.
        threshold: The limits for the variable value
        comp_mode: The comparation mode between the treshold and the latest
        value. Possible values: 'gt', 'gte', 'eq', 'lte', 'less'.
        notif_msg: The notification message template, filled with %s where
        variables should be placed.
        short_notif_msg: A short description of the notification.
        notif_type: The type of the notification to be sent.
        notif_vars: The variables for the notif_msg template. These should be
        valid variable id's or one of the following strings: 'value' or
        'threshold'.
        notif_vars_modifiers: Modifiers for the notif_vars. Can be None if
        there is no modifier or a number with witch the value will be divided.
        tracker_manager: A TrackerManager object.
        cooldown: Number of seconds to wait before we send another notification
        (if needed).
        track_type: Tracking type of the variable. Can be: raw, average or
        differential.
        time_interval_size: If the track_type is average or differential,
        then the time interval to compute them.
        """
        self.tracker_manager = tracker_manager
        self.measurement_manager = measure_manager
        self.var_id = varid
        self.latest_value = None
        self.cooldown = cooldown
        self.cooling_down_end = 0.0
        self.cooling_down = False
        self.threshold = threshold
        self.comp_mode = comp_mode
        self.notif_type = notif_type
        self.notif_msg = notif_msg
        self.short_notif_msg = short_notif_msg
        self.notif_vars = notif_vars
        self.notif_vars_modifiers = notif_vars_modifiers
        self.track_type = track_type
        self.start_up_time = time.time()
        self.ramp_up_done = False
        self.time_interval_size = time_interval_size
        self.shutdown = False

        if track_type == DeviceValueTracker.differential or\
                track_type == DeviceValueTracker.average:
            self.measurement_reducer = MeasurementReducer(time_interval_size)


    def check_ramp_up(self):
        if self.ramp_up_done or self.track_type == DeviceValueTracker.raw:
            return True
        if self.track_type == DeviceValueTracker.differential or\
                self.track_type == DeviceValueTracker.average:
            current_time = time.time()
            if self.start_up_time + self.time_interval_size < current_time:
                self.ramp_up_done = True


    def check_cooldown(self):
        if self.cooling_down:
            crt_time = time.time()
            if crt_time < self.cooling_down_end:
                return False
        return True


    def check_value(self):
        """ Checks that the value is under the given limits """
        if self.shutdown:
            return

        # If we are cooling down, we shouldn't send a notification
        if not self.check_cooldown():
            return

        # Compute the latest value
        temp_latest_value = self.measurement_manager.get_variable(self.var_id)
        if temp_latest_value is None:
            # The Measurement Manager isn't ready to give us the value
            return
        self.latest_value = temp_latest_value

        if self.track_type == DeviceValueTracker.average:
            self.measurement_reducer.add_measurement(self.latest_value)
            self.latest_value = self.measurement_reducer.get_average()
        if self.track_type == DeviceValueTracker.differential:
            self.measurement_reducer.add_measurement(self.latest_value)
            self.latest_value = self.measurement_reducer.get_differential()

        # Make sure we don't give alerts too early when the average or
        # differential isn't yet computed with enough elements
        if not self.check_ramp_up():
            return

        # Check the current value and start cooling down if we should send a
        # notification.
        if self.value_over_limits():
            info_str = 'Device Sensor:\n'
            info_str += 'Variable %s is over the limit %s. Current_value: %s\n'
            info_str += 'Generating a notification ...'
            logging.info(info_str, self.var_id, str(self.var_id),\
                         str(self.latest_value))
            self.alert()
            self.cooling_down = True
            self.cooling_down_end = time.time() + self.cooldown


    def value_over_limits(self):
        if self.comp_mode == DeviceValueTracker.greater and\
                self.latest_value > self.threshold:
            return True
        if self.comp_mode == DeviceValueTracker.less and\
                self.latest_value < self.threshold:
            return True
        if self.comp_mode == DeviceValueTracker.greater_equal and\
                self.latest_value >= self.threshold:
            return True
        if self.comp_mode == DeviceValueTracker.less_equal and\
                self.latest_value <= self.threshold:
            return True
        if self.comp_mode == DeviceValueTracker.equal and\
                self.latest_value == self.threshold:
            return True
        return False


    def alert(self, is_report=False):
        if self.var_id is not None:
            logging.debug('Sending an DeviceSensor alert for %s', self.var_id)
        else:
            logging.debug('Sending an Device Sensor report ...')
        
        # Format the message
        error_str = 'Failed parsing notification message for '
        error_str += 'DeviceSensor Tracker tracking %s\n' % self.var_id
        error_str += 'Shutting down tracker ...'
        
        notif_msg_variables = []
        for var in self.notif_vars:
            if var == 'value':
                notif_msg_variables.append(str(self.latest_value))
                continue
            if var == 'threshold':
                notif_msg_variables.append(str(self.threshold))
                continue
            try:
                var_value = self.measurement_manager.get_variable(var)
                if var_value is None:
                    var_value = '[Undefined]'
            except:
                logging.error(error_str, exc_info=True)
                self.shutdown = True
                return
            notif_msg_variables.append(var_value)
        notif_msg_variables = map(self._apply_modifiers,\
                notif_msg_variables, self.notif_vars_modifiers)
        try:
            computed_notif_msg = self.notif_msg % tuple(notif_msg_variables)
        except:
            logging.error(error_str, exc_info=True)
            self.shutdown = True
            return

        try:
            self.tracker_manager.alert(computed_notif_msg, self.notif_type,\
                                       self.short_notif_msg, is_report)
        except:
            logging.error('DeviceSensor tracker failed to alert', exc_info=True)


    def _apply_modifiers(self, var_value, var_modifier):
        if var_modifier is None or (type(var_modifier) != int and\
                type(var_modifier) != float):
            if type(var_value) == float:
                return round(var_value, 2)
            else:
                return var_value

        if (type(var_value) != int and type(var_value) != float)\
                or var_modifier == 0:
            return var_value

        return round(float(var_value)/var_modifier, 2)



class ReportTracker(DeviceValueTracker):
    """ Class used to send a report each self.cooldown seconds """

    def check_value(self):
        if not self.check_cooldown():
            return

        if not self.check_ramp_up():
            return

        self.alert(True)
        self.cooling_down = True
        self.cooling_down_end = time.time() + self.cooldown



class MeasurementGenerator:
    """ An abstract class which does a measurement. """

    def __init__(self, measurement_param=dict()):
        self.latest_value = None
        self.measurement_param = measurement_param


    def get_latest_value(self):
        """
        Returns the latest measured value. By convention, if the latest_value
        is None, the measurement failed or didn't completed.
        """
        return self.latest_value


    def measure(self):
        """ Does the actual measuring. Should be implemented. """
        pass



# Measurement generators -- START

class UptimeGenerator(MeasurementGenerator):
    """
    Computes the number of seconds (floating point precision) of
    the device uptime.
    Availability: Windows, UNIX
    """

    def measure(self):
        self.latest_value = time.time() - psutil.BOOT_TIME


class LoadAverage1Generator(MeasurementGenerator):
    """
    Computes the load average over the last minute.
    Availability: UNIX
    """

    def measure(self):
        if not POSIX:
            self.latest_value = None
        self.latest_value = os.getloadavg[0]


class LoadAverage5Generator(MeasurementGenerator):
    """
    Computes the load average over the last 5 minutes.
    Availability: UNIX
    """

    def measure(self):
        if not POSIX:
            self.latest_value = None
        self.latest_value = os.getloadavg[1]


class LoadAverage15Generator(MeasurementGenerator):
    """
    Computes the load average over the last 15 minutes.
    Availability: UNIX
    """

    def measure(self):
        if not POSIX:
            self.latest_value = None
        self.latest_value = os.getloadavg[2]


class RamAvailableGenerator(MeasurementGenerator):
    """
    Computes the available RAM size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        self.latest_value = psutil.avail_phymem()


class RamUsedGenerator(MeasurementGenerator):
    """
    Computes the used RAM size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        self.latest_value = psutil.used_phymem()


class SwapAvailableGenerator(MeasurementGenerator):
    """
    Computes the available SWAP size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        self.latest_value = psutil.avail_virtmem()


class SwapUsedGenerator(MeasurementGenerator):
    """
    Computes the used swap size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        self.latest_value = psutil.used_virtmem()


class SwapTotalGenerator(MeasurementGenerator):
    """
    Computes the total SWAP size in bytes.
    Availability: Windows, UNIX
    """

    def measure(self):
        self.latest_value = psutil.total_virtmem()


class OpenPortsGenerator(MeasurementGenerator):
    """
    Computes the number of open UDP and TCP ports on the host.
    Warning: Requires super-user access rights.

    Availability: Windows, UNIX
    """

    def measure(self):

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
        self.latest_value = False

    def measure(self):
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
        if self.network_traffic is not None:
            self.latest_value = self.network_traffic.get_received_bytes()


class NetworkSentBytesGenerator(NetworkTrafficGenerator):
    """
    Computes the sent network bytes.
    Availability: Windows, Linux
    """

    def measure(self):
        if self.network_traffic is not None:
            self.latest_value = self.network_traffic.get_sent_bytes()


class NetworkTotalBytesGenerator(NetworkTrafficGenerator):
    """
    Computes the sum of send and received network bytes.
    Availability: Windows, Linux
    """

    def measure(self):
        if self.network_traffic is not None:
            self.latest_value = self.network_traffic.get_sent_bytes() + \
                    self.network_traffic.get_received_bytes()


class NetworkReceivedPacketsGenerator(NetworkTrafficGenerator):
    """
    Computes the number of received packets.
    Availability: Windows, Linux
    """

    def measure(self):
        if self.network_traffic is not None:
            self.latest_value = self.network_traffic.get_received_packets()


class NetworkSentPacketsGenerator(NetworkTrafficGenerator):
    """
    Computes the number of sent packets.
    Availability: Windows, Linux
    """

    def measure(self):
        if self.network_traffic is not None:
            self.latest_value = self.network_traffic.get_sent_packets()


class NetworkTotalPacketsGenerator(NetworkTrafficGenerator):
    """
    Computes the sum of received and sent packets.
    Availability: Windows, Linux
    """

    def measure(self):
        if self.network_traffic is not None:
            self.latest_value = self.network_traffic.get_sent_packets() +\
                    self.network_traffic.get_received_packets()


class NetworkReceivedBpsGenerator(NetworkTrafficGenerator):
    """
    Computes the number of received bytes over the last second from the
    time measure() is called.
    Availability: Windows, Linux
    """

    def measure(self):
        if self.network_traffic is not None:
            self.latest_value = self.network_traffic.get_received_bps()


class NetworkSentBpsGenerator(NetworkTrafficGenerator):
    """
    Computes the number of sent bytes over the last second from the time
    measure() is called.
    Availability: Windows, Linux
    """

    def measure(self):
        if self.network_traffic is not None:
            self.latest_value = self.network_traffic.get_sent_bps()


class NetworkTotalBpsGenerator(NetworkTrafficGenerator):
    """
    Computes the sum between the sent and received bytes over the last second
    from the time measure() is called.
    Availability: Windows, Linux
    """

    def measure(self):
        if self.network_traffic is not None:
            self.latest_value = self.network_traffic.get_sent_bps() +\
                self.network_traffic.get_received_bps()


class RamPercentGenerator(MeasurementGenerator):
    """
    Computes the percent of how much the RAM is used.
    Availability: Windows, UNIX
    """

    def measure(self):
        self.latest_value = float(psutil.used_phymem())/psutil.TOTAL_PHYMEM


class CpuPercentGenerator(MeasurementGenerator):
    """
    Computes the percent of how much the CPU is used.
    Availability: Windows, UNIX
    """

    def __init__(self):
        MeasurementGenerator.__init__(self)
        self.cpu_percent = CpuPercent()
        self.cpu_percent.start()

    def measure(self):
        self.latest_value = self.cpu_percent.get_value()


class PartitionAvailableGenerator(MeasurementGenerator):
    """
    Computes the total available number of bytes on the given list of partitions.
    For UNIX, the partition is given with it's mount point. For Windows, it's
    given by it's drive letter followed by a ':'.
    Availability: Windows, UNIX
    """

    def measure(self):
        if 'partitions' not in self.measurement_param.keys():
            return
        if WIN:
            self.measure_windows()
        if UNIX:
            self.measure_unix()

    def measure_unix(self):
        avail_size = 0
        try:
            for partition in self.measurement_param['partitions']:
                stat = os.statvfs(partition)
                avail_size += stat.f_frsize * stat.f_bavail
        except:
            pass
        self.latest_value = avail_size

    def measure_windows(self):
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
        self.processes_info = ProcessesInfo.get_instance()


    def get_latest_value(self, tracker=None):
        self.measure(True)
        return self.latest_value


    def measure(self, full_measure=False):
        # full_measure is used to do the parsing only when requesting the value
        # since this MeasurementGenerator shouldn't be used for comparations.
        if not full_measure:
            return
        processes_list = self.processes_info.get_info()
        if processes_list is None:
            self.latest_value = None
            return

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
        if self.size is 0:
            return 0.0
        return self.measurements_sum/self.size


    def get_differential(self):
        """
        Returns the difference between the first and last value in the queue.
        """
        queue_len = len(self.queue)
        if queue_len is 0:
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
        self.daemon = True
        self.prev_received_bytes = 0
        self.prev_sent_bytes = 0

        # Used to inform when the object is ready to give relevant statistics
        self.ramp_up = True


    def init_counters(self):
        self.received_bytes = 0
        self.sent_bytes = 0
        self.received_packets = 0
        self.sent_packets = 0
        self.received_bps = 0.0
        self.sent_bps = 0.0


    def get_received_bytes(self):
        self.traffic_lock.acquire()
        temp = self.received_bytes if not self.ramp_up else None
        self.traffic_lock.release()
        return temp


    def get_sent_bytes(self):
        self.traffic_lock.acquire()
        temp = self.sent_bytes if not self.ramp_up else None
        self.traffic_lock.release()
        return temp


    def get_received_packets(self):
        self.traffic_lock.acquire()
        temp = self.received_packets if not self.ramp_up else None
        self.traffic_lock.release()
        return temp


    def get_sent_packets(self):
        self.traffic_lock.acquire()
        temp = self.sent_packets if not self.ramp_up else None
        self.traffic_lock.release()
        return temp


    def get_received_bps(self):
        self.traffic_lock.acquire()
        temp = self.received_bps if not self.ramp_up else None
        self.traffic_lock.release()
        return temp


    def get_sent_bps(self):
        self.traffic_lock.acquire()
        temp = self.sent_bps if not self.ramp_up else None
        self.traffic_lock.release()
        return temp


    def run(self):
        pass

        

class LinuxNetworkTraffic(NetworkTraffic):

    # Time between reading the information in seconds
    sleep_time = 1.0

    @staticmethod
    def get_instance():
        if NetworkTraffic.instance is None:
            NetworkTraffic.instance = LinuxNetworkTraffic()
            NetworkTraffic.instance.start()
        return NetworkTraffic.instance


    def run(self):
        step = 0
        logging.info('Starting up Network Traffic measurement ...')
        while True:
            # Waiting until previous measures are done.
            if step < 2:
                step += 1
            else:
                self.ramp_up = False

            try:
                self.measure_traffic()
            except:
                self.ramp_up = True
                error_msg = 'Device Sensor: Failed to measure network traffic.'
                error_msg += '\nShutting down traffic measurement.'
                logging.error(error_msg)
                return
            time.sleep(LinuxNetworkTraffic.sleep_time)


    def measure_traffic(self):
        try:
            traffic_file = open('/proc/net/dev')
        except:
            return
        traffic_file_lines = traffic_file.readlines()

        self.traffic_lock.acquire()

        self.prev_received_bytes = self.received_bytes
        self.prev_sent_bytes = self.sent_bytes
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

        self.received_bps = (self.received_bytes - self.prev_received_bytes)/\
                            LinuxNetworkTraffic.sleep_time
        self.sent_bps = (self.sent_bytes - self.prev_sent_bytes)/\
                            LinuxNetworkTraffic.sleep_time
        self.traffic_lock.release()



class WindowsNetworkTraffic(NetworkTraffic):

    sleep_time = 5.0

    @staticmethod
    def get_instance():
        if NetworkTraffic.instance is None:
            NetworkTraffic.instance = WindowsNetworkTraffic()
            NetworkTraffic.instance.start()
        return NetworkTraffic.instance


    def run(self):
        pythoncom.CoInitialize()
        _wmi = wmi.WMI()

        step = 0
        logging.info('Starting up Network Traffic measurement ...')
        while True:
            # Waiting until previous measures are done.
            if step < 2:
                step += 1
            else:
                self.ramp_up = False

            # Sleeping since this process takes a lot and it's very CPU
            # intensive
            step_start_time = time.time()
            time.sleep(WindowsNetworkTraffic.sleep_time)
            
            recv_b_temp = 0
            sent_b_temp = 0
            recv_p_temp = 0
            sent_p_temp = 0
            recv_bps_temp = 0.0
            sent_bps_temp = 0.0
            
            args = ['BytesReceivedPersec', 'BytesSentPersec',\
                    'PacketsReceivedPersec', 'PacketsSentPersec']
            interfaces = _wmi.Win32_PerfRawData_Tcpip_NetworkInterface(args)
            for interface in interfaces:
                recv_b_temp += int(interface.BytesReceivedPersec)
                sent_b_temp += int(interface.BytesSentPersec)
                recv_p_temp += int(interface.PacketsReceivedPersec)
                sent_p_temp += int(interface.PacketsSentPersec)
            step_end_time = time.time()

            # Computing the new values
            self.traffic_lock.acquire()
            self.prev_received_bytes = self.received_bytes
            self.prev_sent_bytes = self.sent_bytes
            self.received_bytes = recv_b_temp
            self.sent_bytes = sent_b_temp
            self.received_packets = recv_p_temp
            self.sent_packets = sent_p_temp
            self.received_bps = (self.received_bytes -\
                    self.prev_received_bytes)/(step_end_time - step_start_time)
            self.sent_bps = (self.sent_bytes - self.prev_sent_bytes)/\
                    (step_end_time - step_start_time)
            self.traffic_lock.release()
            
        pythoncom.CoUninitialize()



class ProcessesInfo(Thread):

    instance = None

    def __init__(self):
        """ Singletone: Don't call directly. Use get_instance() """
        Thread.__init__(self)
        self.daemon = True
        self.ramp_up = True

        # Init the processes cpu%
        pid_list = psutil.get_pid_list()
        self.processes = {}
        self.processes_info = None
        self.processes_lock = Lock()
        for pid in pid_list:
            try:
                self.processes[pid] = psutil.Process(pid)
                self.processes[pid].get_cpu_percent(interval=0)
            except:
                del self.processes[pid]


    @staticmethod
    def get_instance():
        if ProcessesInfo.instance is None:
            ProcessesInfo.instance = ProcessesInfo()
            ProcessesInfo.instance.start()
        return ProcessesInfo.instance


    def run(self):
        logging.info('Starting DeviceSensor ProcessesInfo ...')
        while True:
            self.compute_new_information()
            time.sleep(3.0)


    def compute_new_information(self):
        current_pid_list = psutil.get_pid_list()
        old_pid_list = self.processes.keys()
        new_pid_list = [x for x in current_pid_list if not x in old_pid_list]

        # Delete dead processes
        for pid in old_pid_list:
            if pid not in current_pid_list:
                del self.processes[pid]

        # Add new processes
        for pid in new_pid_list:
            try:
                self.processes[pid] = psutil.Process(pid)
                self.processes[pid].get_cpu_percent(interval=0)
            except:
                try:
                    del self.processes[pid]
                except:
                    pass

        # First measure. Results won't be relevant at this point
        if self.ramp_up:
            self.ramp_up = False
            return

        new_processes_info = []
        today_day = datetime.date.today()
        for proc in self.processes.values():
            try:
                proc_info = []
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

                # Using a list instead of a dict here since this operation
                # needs to be finished fast.
                proc_info.append(user)
                proc_info.append(pid)
                proc_info.append(cpu)
                proc_info.append(mem)
                proc_info.append(vsz)
                proc_info.append(rss)
                proc_info.append(start)
                proc_info.append(cputime)
                proc_info.append(cmd)
                new_processes_info.append(proc_info)
            except:
                # The process died before we got to it in this loop
                del self.processes[proc.pid]
                pass

        self.processes_lock.acquire()
        self.processes_info = new_processes_info
        self.processes_lock.release()


    def get_info(self):
        # If it's too early, then we don't have any relevant information
        if self.ramp_up:
            return None
        self.processes_lock.acquire()
        temp = self.processes_info
        self.processes_lock.release()
        return temp

    
        
class CpuPercent(Thread):
    """
    Class to measure the cpu%.
    This is needed because succesive calls to psutil.cpu_percent() with
    interval set to None won't give accurate results (in the current psutil
    release).

    Calling with interval=0.2 will make the thread sleep for 0.2 seconds.
    """

    def __init__(self):
        Thread.__init__(self)
        self.cpu_percent = psutil.cpu_percent(interval=0.5)
        self.cpu_percent_lock = Lock()
        self.daemon = True



    def run(self):
        logging.info('Starting up DeviceSensor CpuPercent ...')
        while True:
            temp = psutil.cpu_percent(interval=0.4)
            self.cpu_percent_lock.acquire()
            self.cpu_percent = temp
            self.cpu_percent_lock.release()


    def get_value(self):
        self.cpu_percent_lock.acquire()
        temp = self.cpu_percent
        self.cpu_percent_lock.release()
        return temp/100.0


        
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
