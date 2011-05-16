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

import json
import time
import socket

class NotificationTypes:

    info = "INFO"
    warning = "WARNING"
    recovery = "RECOVERY"
    critical = "CRITICAL"
    emergency = "EMERGENCY"



class NotificationFields:

    source_host = 'SourceHost'
    timestamp = 'Timestamp'
    message = 'Message'
    message_type = 'Type'
    monitoring_module = 'MonitoringModule'
    module_fields = 'ModuleFields'



class NotificationParser:

    @staticmethod
    def parse(message, msg_type, fields):
        """Parses the message into the internal format (JSON)"""
        message_obj = dict()
        message_obj[NotificationFields.message] = message
        message_obj[NotificationFields.message_type] = msg_type
        message_obj[NotificationFields.timestamp] = time.time()
        # TODO : get the IP address of the Host
        message_obj[NotificationFields.source_host] = socket.gethostname()
        message_obj[NotificationFields.module_fields] = dict()
        for i in fields.keys():
            message_obj[NotificationFields.module_fields][i] = fields[i]

        return json.dumps(message_obj)
