#!/usr/bin/env python
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

from threading import Thread
from threading import Lock
from threading import Semaphore
import time
import traceback
import json
from copy import copy
import socket
import ssl

from umit.inventory.common import message_delimiter


class NIServerCommunicator(Thread):

    connect_timeout = 2.0

    def __init__(self, core, conf):
        Thread.__init__(self)

        self.core = core
        self.connected = False
        self.should_shutdown = False
        self.shutdown_lock = Lock()
        self.login_semaphore = Semaphore(0)

        self.connect_request = False
        self.data_sock = None
        self.buffer = ''

        # Mapping request ID's to actual requests
        self.requests = {}


    def run(self):
        # Wait for a connect attempt

        while True:
            self.shutdown_lock.acquire()
            if self.should_shutdown:
                self.shutdown_lock.release()
                break
            self.shutdown_lock.release()

            if not self.connected and self.connect_request:
                self.attempt_connect_to_server()
                self.connect_request = False
                time.sleep(0.5)
            elif self.connected:
                # Get the next message from the server. Test if the server
                # closed the connection.
                try:
                    msg = self._recv(self.data_sock, self.buffer,\
                                     use_delimiter=True)
                    print msg
                except:
                    self.core.set_connection_closed()


    def shutdown(self):
        self.shutdown_lock.acquire()
        self.should_shutdown = True
        if not self.connected:
            self.login_semaphore.release()
        self.shutdown_lock.release()


    def connect(self, uname, password, host, port, ssl_enabled):
        self.username = uname
        self.password = password
        self.host = host
        self.port = port
        self.ssl_enabled = ssl_enabled
        self.connect_request = True


    def attempt_connect_to_server(self):
        # Initialize the request to send it
        request = ConnectRequest(self.username, self.password,\
                                 self.ssl_enabled)

        # Send the request to connect
        sock = socket.socket()
        sock.settimeout(NIServerCommunicator.connect_timeout)
        sock = ssl.wrap_socket(sock)
        try:
            sock.connect((self.host, self.port))
        except:
            self.core.set_login_failed('Notifications Server Not Reachable')

        send_ok = self._send(sock, request.serialize(), True)
        print send_ok
        if not send_ok:
            self.core.set_login_failed('Notifications Server Not Reachable')

        # Wait for the response
        buffer = ''
        response = self._recv(sock, buffer, use_delimiter=True)
        print response
        sock.close()
        if response is None:
            self.core.set_login_failed('Authentication Denied By Server')
            return

        self.parse_connect_response(response, request.request_id)


    def parse_connect_response(self, response, req_id):
        try:
            r = json.loads(response)
        except:
            self.core.set_login_failed('Bad Response from Server')
            traceback.print_exc()
            return

        try:
            response_code = int(r['response_code'])
        except:
            self.core.set_login_failed('Authentication Denied By Server')
            traceback.print_exc()
            return

        # Test if our authentication was accepted
        if response_code != 200:
            self.core.set_login_failed('Authentication Denied By Server')
            return

        try:
            response_id = int(r['request_id'])
            body = r['body']
            permissions = body['permissions']
            token = body['token']
            data_port = int(body['data_port'])
            encryption_enabled = bool(body['encryption_enabled'])
        except:
            self.core.set_login_failed('Bad Response From Server')
            traceback.print_exc()
            return

        if req_id != response_id:
            self.core.set_login_failed('Bad Response From Server')
            return

        self.data_sock = socket.socket()
        if encryption_enabled:
            print 'aici'
            self.data_sock = ssl.wrap_socket(self.data_sock)

        try:
            self.data_sock.connect((self.host, data_port))
            self.data_sock.settimeout(NIServerCommunicator.connect_timeout)
            self._send(self.data_sock, token, False)
            self.data_sock.settimeout(0)
        except:
            self.core.set_login_failed('Connection Closed By Server')
            traceback.print_exc()
            return

        self.connected = True


    def _send(self, sock, data, include_delimiter=True):
        if include_delimiter:
            data = str(data) + message_delimiter

        total_sent_b = 0
        length = len(data)

        try:
            while total_sent_b < length:
                sent = sock.send(data[total_sent_b:])
                if sent is 0:
                    return False
                total_sent_b += sent
        except:
            traceback.print_exc()
            return False

        return True


    def _recv(self, sock, buffer, size=-1, use_delimiter=False):
        """
        Only one of size and delimiter must be given:
        * If size is not -1, then it must be a strict positive number and in
          this method we will read size bytes from the given socket (sock).
        * If delimiter is not False, then we will read bytes from the socket
          until we reached the message_delimiter.

        A buffer must also be given so remaining bytes after the delimiter
        will be stored in the buffer and won't be lost.
        The actual received message will be returned in both cases (or None
        if a network error occurred).
        """

        if size <= -1 and use_delimiter is None:
            err_msg = 'ServerCommunicator.py: _recv called with size and delim'
            err_msg += ' both Null.'
            raise Exception(err_msg)

        if size > -1:
            temp_buffer = copy(buffer)
            while len(temp_buffer) < size:
                try:
                    chunk = sock.recv(size - len(temp_buffer))
                except:
                    traceback.print_exc()
                    return None
    
                if chunk == '':
                    return None
                temp_buffer += chunk
            buffer = []
            return True
        elif use_delimiter:
            chunk = []
            while message_delimiter not in chunk:
                try:
                    chunk = sock.recv(1024)
                except:
                    traceback.print_exc()
                    return None

                if chunk == '':
                    return None
                buffer += chunk
            buffer_parts = buffer.split(message_delimiter)
            buffer = buffer_parts[1]
            return buffer_parts[0]



class Request:
    """ A Request to be sent to the Notifications Server """

    last_sent_req_id = 0

    def __init__(self, username, password, body, target='GENERAL'):
        self.username = username
        self.password = password
        self.target = target
        self.body = body
        self.request_id = self.last_sent_req_id
        self.last_sent_req_id += 1


    def serialize(self):
        req = dict()
        req['username'] = self.username
        req['password'] = self.password
        req['request_id'] = self.request_id
        req['target'] = self.target
        req['body'] = self.body

        return json.dumps(req)


    def receive_response(self):
        """
        Called when a response was received for a request.
        Should be overwritten if needed.
        """
        pass



class ConnectRequest(Request):

    def __init__(self, username, password, ssl_enabled):

        connect_general_request = dict()
        connect_general_request['enable_encryption'] = ssl_enabled

        general_request = dict()
        general_request['general_request_type'] = 'CONNECT'
        general_request['general_request_body'] = connect_general_request

        Request.__init__(self, username, password, general_request)