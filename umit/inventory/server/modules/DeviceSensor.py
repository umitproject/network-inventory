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

from umit.inventory.server.Module import ServerModule
from umit.inventory.server.ServerInterface import ServerInterface
from umit.inventory.server.ServerInterfaceMessages import ResponseFields

import logging
import json


class DeviceSensor(ServerModule):

    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)

        self.agent_tracker = None
        self.command_tracker = None

        self.device_sensor_host_info = {}

        self.request_handlers = {
            'REAL_TIME_REQUEST' : self.handle_real_time_request,
            'REAL_TIME_CLOSE' : self.handle_real_time_close,
            'GET_NOTIFICATION_COND' : self.handle_get_notification_cond,
            'SET_NOTIFICATION_COND' : self.handle_set_notification_cond,
            'GET_REPORT_TEMPLATE' : self.handle_get_report_template,
            'SET_REPORT_TEMPLATE' : self.handle_set_report_template,
        }

        # Mapping tuples of gui hostnames and request id's to command id's
        self.active_command_connections = dict()


    def activate(self):
        logging.info('DeviceSensor: Activating module ...')

        # Get the Agent tracker and Command Tracker
        self.agent_listener = self.shell.get_module('AgentListener')
        if self.agent_listener is None:
            err_msg = 'DeviceSensor: Required AgentListener module not installed'
            logging.error(err_msg)
            return

        self.command_tracker = self.agent_listener.command_tracker
        self.agent_tracker = self.agent_listener.agent_tracker


    def deactive(self):
        logging.info('DeviceSensor: Deactivating module ...')


    def refresh_settings(self):
        pass


    def get_name(self):
        return 'DeviceSensor'


    def init_default_settings(self):
        pass


    def init_database_operations(self):
        pass


    def evaluate_request(self, request, data_connection):
        logging.debug('DeviceSensor: Evaluating request ...')
        
        req_id = request.get_request_id()
        device_sensor_request = DeviceSensorRequest(request)
        if not device_sensor_request.sanity_check():
            logging.warning('DeviceSensor: Invalid request')
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        if self.command_tracker is None:
            logging.warning('DeviceSensor: CommandTracker not found')
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        request_type = device_sensor_request.get_type()
        try:
            self.request_handlers[request_type](device_sensor_request, req_id,
                                                data_connection)
        except:
            logging.warning('DeviceSensor: Invalid request type', exc_info=True)


    def handle_real_time_request(self, device_sensor_request, req_id,
                                 data_connection):
        agent_hostname = device_sensor_request.get_agent_hostname()

        command_id = self.command_tracker.send_command(
            agent_hostname, 'DeviceSensor', 'REAL_TIME_REQUEST',
            handler_function=self.real_time_command_callback,
            handler_user_data=data_connection)

        if command_id is None:
            logging.warning('DeviceSensor: Error sending command')
            response = ServerInterface.build_internal_error_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        gui_hostname = data_connection.peer_host
        self.active_command_connections[(gui_hostname, req_id)] =\
            command_id


    def real_time_command_callback(self, message, command_id,
        handler_user_data, command_connection, closed=False):
        if closed:
            logging.debug('DeviceSensor: Command Connection %d closed',
                          command_id)
            return

        response = ServerInterface.build_accepted_response(-1)
        response[ResponseFields.response_type] = 'DEVICE_SENSOR_REAL_TIME_REQUEST'
        response[ResponseFields.body] = message

        data_connection = handler_user_data
        sent_ok = data_connection.send_message(json.dumps(response), True)

        # Check the requesting application didn't went down
        if not sent_ok:
            return False

        return True


    def handle_real_time_close(self, device_sensor_request, req_id,
                               data_connection):
        close_request = DeviceSensorRealTimeClose(device_sensor_request)
        if not close_request.sanity_check():
            response = ServerInterface.build_invalid_response(req_id)
            data_connection.send_message(json.dumps(response), True)
            return

        original_req_id = close_request.get_request_id()
        gui_hostname = data_connection.peer_host
        try:
            command_id = self.active_command_connections[(gui_hostname,
                                                          original_req_id)]
            agent_hostname = device_sensor_request.get_agent_hostname()
            self.command_tracker.close_command_connection(agent_hostname,
                                                          command_id)
        except:
            pass

        response = ServerInterface.build_accepted_response(req_id)
        data_connection.send_message(json.dumps(response), True)
        

    def handle_get_notification_cond(self, device_sensor_request,
                                     req_id, data_connection):
        #TODO
        pass


    def handle_set_notification_cond(self, device_sensor_request,
                                     req_id, data_connection):
        #TODO
        pass



    def handle_get_report_template(self, device_sensor_request,
                                   req_id, data_connection):
        #TODO
        pass


    def handle_set_report_template(self, device_sensor_request,
                                   req_id, data_connection):
        #TODO
        pass


    def shutdown(self):
        pass



class DeviceSensorRequest:

    def __init__(self, request):
        self.request = request

        self.type = None
        self.body = None
        self.agent_hostname = None


    def sanity_check(self):
        """ Checks the fields. Must be called after initialization """
        # Check the type
        try:
            self.type = self.request.body[DeviceSensorRequestBody.type]
        except:
            err_msg = 'ServerInterface: Missing type from device sensor request'
            logging.warning(err_msg)
            return False

        # Check the body (optional)
        if DeviceSensorRequestBody.body in self.request.body:
            self.body = self.request.body[DeviceSensorRequestBody.body]

        # Check the agent hostname
        try:
            self.agent_hostname =\
                self.request.body[DeviceSensorRequestBody.agent_hostname]
        except:
            err_msg = 'ServerInterface: Missing hostname from device'
            err_msg += ' sensor request'
            logging.warning(err_msg)
            return False

        return True


    def get_type(self):
        return self.type


    def get_body(self):
        return self.body


    def get_agent_hostname(self):
        return self.agent_hostname



class DeviceSensorRealTimeClose:

    def __init__(self, device_sensor_request):
        self.body = device_sensor_request.get_body()

        self.req_id = None


    def sanity_check(self):
        try:
            self.req_id = self.body[DeviceSensorRealTimeCloseBody.req_id]
        except:
            err_msg = 'ServerInterface: Missing req_id from device sensor'
            err_msg += ' real time stop request'
            logging.warning(err_msg)
            return False
        
        return True


    def get_request_id(self):
        return self.req_id



class DeviceSensorRequestBody:
    """
    * type: The type of the request. This can have one of the
      following values:
      - "REAL_TIME_REQUEST": The requesting side wants to receive real time
        information about the device CPU%, RAM%, Network Received and Sent
        bytes over the last second.
      - "REAL_TIME_CLOSE": The requesting wants to stop receiving real time
        information.
      - "GET_NOTIFICATION_COND": Get the JSON with the associated notification
        conditions for the Device Sensor.
      - "SET_NOTIFICATION_COND": Set the JSON with the associated notification
        conditions for the Device Sensor.
      - "GET_REPORT_TEMPLATE": Get the pre-formatted body of the report.
      - "SET_REPORT_TEMPLATE": Set the pre-formatted body of the report.
    * body: The body of the request.
    * agent_hostname: The hostname on which the agent is installed.
    """
    type = 'device_sensor_type'
    body = 'device_sensor_body'
    agent_hostname = 'agent_hostname'



class DeviceSensorRealTimeCloseBody:
    """
    The fields for the body of the request when type is "REAL_TIME_CLOSE":
    * req_id: The request id of the original "REAL_TIME_REQUEST".
    """
    req_id = 'req_id'