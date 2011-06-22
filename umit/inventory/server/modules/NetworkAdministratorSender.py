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

from umit.inventory.server.Module import SubscriberServerModule
from umit.inventory.server.Module import ServerModule

import traceback
import json
import httplib
import urllib
import time
import base64
from threading import Thread, Lock


class NetworkAdministratorSender(ServerModule, SubscriberServerModule):

    # Options
    username = 'username'
    password = 'password'
    host = 'host'
    queue_size = 'notification_queue_size'
    wait_time = 'max_wait_time'
    
    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)

        self.username = self.options[NetworkAdministratorSender.username]
        self.password = self.options[NetworkAdministratorSender.password]
        self.host = self.options[NetworkAdministratorSender.host]
        self.max_qsize = int(self.options[NetworkAdministratorSender.queue_size])
        self.wait_time = float(self.options[NetworkAdministratorSender.wait_time])

        self.dispatcher = NotificationQueueDispatcher(self.host, self.username,\
                self.password, self.max_qsize, self.wait_time)
        self.dispatcher.start()
        
        
    def get_name(self):
        return 'NetworkAdministratorSender'


    def init_default_settings(self):
        self.options[NetworkAdministratorSender.username] = 'guest'
        self.options[NetworkAdministratorSender.password] = 'guest'
        self.options[NetworkAdministratorSender.host] = 'ns-dev.appspot.com'
        self.options[NetworkAdministratorSender.queue_size] = 2
        self.options[NetworkAdministratorSender.wait_time] = 7.5


    def receive_notification(self, notification):
        """
        Called when receiving a notification. Will add to the queue and
        send the queue content to the server if needed.
        """
        self.dispatcher.add_notification(notification)

        
    def subscribe(self):
        # Subscribing to all notifications
        self.shell.subscribe(self)



class NotificationQueueDispatcher(Thread):

    def __init__(self, host, username, password, max_qsize, wait_time):
        Thread.__init__(self)
        self.daemon = True

        self.host = host
        self.username = username
        self.password = password
        self.max_qsize = max_qsize
        self.wait_time = wait_time

        # Queue related variables
        self.queue = []
        self.queue_lock = Lock()
        self.last_sent_time = time.time()

        
    def check_time(self):
        """ Checks if the time expired for waiting on maxing the queue size """
        if time.time() - self.last_sent_time > self.wait_time:
            return True
        return False


    def add_notification(self, notification):
        """
        Adds a notification to the queue.
        If the size reached it's limits, it will send the notification to the
        Network Administrator.
        """
        self.queue_lock.acquire()
        self.queue.append(notification.fields)

        if len(self.queue) >= self.max_qsize:
            self.send_queue_content()
        self.queue_lock.release()


    def run(self):
        while True:
            # Check the notifications
            if self.check_time():
                self.queue_lock.acquire()
                self.send_queue_content()
                self.queue_lock.release()
            time.sleep(0.2)


    def send_queue_content(self):
        """
        Sends the queue content to the Network Administrator. At this point the
        queue may be empty if a notification was added right after we checked
        the time.
        """
        if len(self.queue) == 0:
            return

        conn = httplib.HTTPConnection(self.host)

        # TODO send the notifications
        print self.queue
        sent_message = json.dumps(self.queue)
        auth_string = get_auth_string(self.username, self.password)
        headers = {'Authorization' : auth_string}
        sent_dict = {'events' : sent_message}
        params = urllib.urlencode(sent_dict)
        conn.request("POST", "/api/event/report/", params, headers)
        response = conn.getresponse()
        print response.status
        print response.reason
        print response.msg
        print response.getheaders()
        print 'sending %d %f' % (len(self.queue), time.time())
        
        conn.close()
        
        self.queue = []
        self.queue_size = 0
        self.last_sent_time = time.time()


    
def get_auth_string(username, password):
    """ Helper function - returns basic authentication string """
    auth = '%s:%s' % (username, password)
    auth_string = 'Basic %s' % base64.encodestring(auth)
    auth_string = auth_string.strip()
    return auth_string