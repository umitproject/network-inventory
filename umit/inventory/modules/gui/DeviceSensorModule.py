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

from umit.inventory.gui.Module import Module
from umit.inventory.gui.HostsViewManager import AbstractHostsView
from umit.inventory.gui.ServerCommunicator import Request

import os
import time
import gtk
from threading import Thread
from threading import Lock

from pygtk_chart import line_chart
import pygtk_chart

import gobject
import traceback
from copy import copy


class DeviceSensorModule(Module):

    def __init__(self, ui_manager, shell):
        Module.__init__(self, ui_manager, shell)

        self.server_configs = None


    def set_configs(self, configs):
        self.server_configs = configs


    def add_configs_ui(self, config_window_manager):
        pass


    def add_notebook_page(self, notebook):
        """
        Called when the module should add pages to the general GUI notebook.
        Should be implemented.
        """
        pass


    def get_host_views(self):
        """
        Returns a list of host views (which implement AbstractHostView) to
        be added to the 'Network Hosts' tab.
        Should be implemented.
        """
        return [DeviceSensorHostView(self.shell.ui_manager)]


    def get_event_widget(self, notification):
        """
        Called when the module should return a widget that will show details
        from the notification. If the notification isn't meant for this module
        then None should be returned.
        Should be implemented.
        """
        return None


    def get_event_window_name(self):
        """
        Returns the name that will be shown in the event window when showing
        information from this module.
        Should be implemented.
        """
        return None



class DeviceSensorHostView(AbstractHostsView):

    def __init__(self, ui_manager):
        self.ui_manager = ui_manager
        self.shell = ui_manager.shell

        self.hostname = None
        self.widget = None
        self.graph_tracker = None
        
        # The request id for the request that is currently sending graph data
        self.active_request_id = None

        # Register the handler
        self.shell.register_async_handler('DEVICE_SENSOR_REAL_TIME_REQUEST',
            self.real_time_request_handler)

        self.os_id_to_pixmap_file = {
            'windows' : self.get_os_pixmap('win_75.png'),
            'linux' : self.get_os_pixmap('linux_75.png'),
            'freebsd' : self.get_os_pixmap('freebsd_75.png'),
            'openbsd' : self.get_os_pixmap('openbsd_75.png'),
            'mac' : self.get_os_pixmap('macosx_75.png'),
            'other' : self.get_os_pixmap('default_75.png'),
            'unknown' : self.get_os_pixmap('unknown_75.png'),
        }


    def get_os_pixmap(self, name):
        return self.ui_manager.get_pixmap_file_path(name)


    def get_name(self):
        return "Host Info"


    def _build_objects(self):
        glade_file_name =\
            self.ui_manager.get_glade_file_path('ni_device_sensor_host_view.glade')
        builder = gtk.Builder()
        builder.add_from_file(glade_file_name)

        self.widget = builder.get_object('host_view_top')
        self.widget.unparent()

        self.os_image = builder.get_object('os_image')

        self.os_label = builder.get_object('os_label')
        self.state_label = builder.get_object('state_label')
        self.hostname_label = builder.get_object('hostname_label')
        self.ip_label = builder.get_object('ip_label')
        self.uptime_label = builder.get_object('uptime_label')
        self.cpu_label = builder.get_object('cpu_label')
        self.ram_label = builder.get_object('ram_label')

        self.cpu_graph_container = builder.get_object('cpu_graph_container')
        self.ram_graph_container = builder.get_object('ram_graph_container')
        self.recv_bps_container = builder.get_object('recv_bps_container')
        self.sent_bps_container = builder.get_object('sent_bps_container')

        self._build_graphs()


    def _build_graphs(self):
        self.ram_chart = line_chart.LineChart()
        self.ram_chart.set_xrange((0, 20))
        self.ram_chart.set_yrange((0, 1))
        self.ram_chart.grid.set_property('visible', False)
        self.ram_chart.xaxis.set_property('visible', False)
        self.ram_chart.yaxis.set_property('visible', False)
        self.ram_graph_container.add(self.ram_chart)
        self.ram_chart.show()

        self.cpu_chart = line_chart.LineChart()
        self.cpu_chart.set_xrange((0, 20))
        self.cpu_chart.set_yrange((0, 1))
        self.cpu_chart.grid.set_property('visible', False)
        self.cpu_chart.xaxis.set_property('visible', False)
        self.cpu_chart.yaxis.set_property('visible', False)
        self.cpu_graph_container.add(self.cpu_chart)
        self.cpu_chart.show()

        self.sent_bps_chart = line_chart.LineChart()
        self.sent_bps_chart.set_xrange((0, 20))
        self.sent_bps_chart.set_yrange((0, 1000))#line_chart.RANGE_AUTO)
        self.sent_bps_chart.grid.set_property('visible', False)
        self.sent_bps_chart.xaxis.set_property('visible', False)
        self.sent_bps_chart.yaxis.set_property('visible', False)
        self.sent_bps_container.add(self.sent_bps_chart)
        self.sent_bps_chart.show()

        self.recv_bps_chart = line_chart.LineChart()
        self.recv_bps_chart.set_xrange((0, 20))
        self.recv_bps_chart.set_yrange((0, 1000))#line_chart.RANGE_AUTO)
        self.recv_bps_chart.grid.set_property('visible', False)
        self.recv_bps_chart.xaxis.set_property('visible', False)
        self.recv_bps_chart.yaxis.set_property('visible', False)
        self.recv_bps_container.add(self.recv_bps_chart)
        self.recv_bps_chart.show()

        # Set background colors
        self.ram_chart.background.set_gradient([0.3, 0.3, 0.3], [0, 0, 0])
        self.cpu_chart.background.set_gradient([0.3, 0.3, 0.3], [0, 0, 0])
        self.sent_bps_chart.background.set_gradient([0.3, 0.3, 0.3], [0, 0, 0])
        self.recv_bps_chart.background.set_gradient([0.3, 0.3, 0.3], [0, 0, 0])



    def _set_widget_values(self):
        if self.hostname is None:
            return

        self.hostname_label.set_markup('<b>%s</b>' % self.hostname)
        ip_addr = self.shell.get_host_ipv4_address(self.hostname)
        if ip_addr is not None:
            self.ip_label.set_markup('<b>%s</b>' % ip_addr)


    def get_widget(self):
        self._build_objects()
        self.graph_tracker = GraphTracker(self.cpu_chart, self.ram_chart,
                                          self.sent_bps_chart,
                                          self.recv_bps_chart,
                                          21.0)
        self.graph_tracker.start()
        self._set_widget_values()
        return self.widget


    def _close_active_request(self):
        if self.active_request_id is None:
            return

        # Send the request
        username = self.shell.get_username()
        password = self.shell.get_password()
        request = DeviceSensorRealTimeClose(username, password, self.hostname,
                                            self.active_request_id)

        self.shell.send_request(request)


    def deactivate(self):
        pass


    def set_host(self, hostname):
        self._close_active_request()

        if self.graph_tracker is not None:
            self.graph_tracker.shutdown()

        self.hostname = hostname

        if hostname is None:
            self.active_request_id = None
            self.graph_tracker = None
            return

        # Send the request
        username = self.shell.get_username()
        password = self.shell.get_password()
        real_time_request = DeviceSensorRealTimeRequest(username, password,
                                                        hostname, self)
        self.shell.send_request(real_time_request)
        self.active_request_id = real_time_request.request_id
        
        if self.widget is None:
            return

        self._set_widget_values()


    def real_time_request_handler(self, body):
        # Get the data
        body_fields = body.keys()
        if 'boot_time' in body_fields:
            self._set_boot_time(body['boot_time'])
        if 'cpu' in body_fields:
            self._set_cpu(body['cpu'])
        if 'ram' in body_fields:
            self._set_ram(body['ram'])
        if 'os_id' in body_fields:
            self._set_os_id(body['os_id'])
        if 'os_name' in body_fields:
            self._set_os_name(body['os_name'])
        if 'cpu_percent' in body_fields:
            self._set_cpu_percent(body['cpu_percent'])
        if 'ram_percent' in body_fields:
            self._set_ram_percent(body['ram_percent'])
        if 'recv_bps' in body_fields:
            self._set_recv_bps(body['recv_bps'])
        if 'sent_bps' in body_fields:
            self._set_sent_bps(body['sent_bps'])
        if 'state' in body_fields:
            self._set_state(body['state'])


    def _set_state(self, state):
        if state == 'UP':
            markup = '<b><span foreground=\'#245900\'>UP</span></b>'
            self.state_label.set_markup(markup)
        if state == 'DOWN':
            markup = '<b><span foreground=\'#B50D0D\'>DOWN</span></b>'
            self.state_label.set_markup(markup)


    def _set_boot_time(self, boot_time):
        current_time = time.time()

        total_seconds = int(current_time - boot_time)
        seconds = total_seconds % 60

        total_minutes = int(total_seconds/60)
        minutes = total_minutes % 60

        total_hours = int(total_minutes/60)
        hours = total_hours % 24

        days = int(total_hours/24)

        if days > 0:
            uptime_str = '%d days, %d hours, %d minutes, %d seconds' %\
                         (days, hours, minutes, seconds)
        elif hours > 0:
            uptime_str = '%d hours, %d minutes, %d seconds' %\
                         (hours, minutes, seconds)
        elif minutes > 0:
            uptime_str = '%d minutes, %d seconds' %\
                         (minutes, seconds)
        else:
            uptime_str = '%d seconds' % seconds

        self.uptime_label.set_markup('<b>%s</b>' % uptime_str)
        

    def _set_os_id(self, os_id):
        try:
            self.os_image.set_from_file(self.os_id_to_pixmap_file[os_id])
        except:
            self.os_image.set_from_file(default_logo_path)


    def _set_os_name(self, os_name):
        self.os_label.set_markup('<b>%s</b>' % os_name)


    def _set_cpu(self, cpu_name):
        self.cpu_label.set_markup('<b>%s</b>' % cpu_name)


    def _set_ram(self, ram_size):
        mb_ram_size = ram_size/(1024.0 * 1024.0)
        if mb_ram_size < 1024:
            self.ram_label.set_markup('<b>%.2f Mb</b>' % mb_ram_size)
            return
        gb_ram_size = mb_ram_size/1024.0
        self.ram_label.set_markup('<b>%2.f Gb</b>' % gb_ram_size)


    def _set_cpu_percent(self, cpu_percent):
        self.graph_tracker.add_points(cpu_y=cpu_percent)


    def _set_ram_percent(self, ram_percent):
        self.graph_tracker.add_points(ram_y=ram_percent)


    def _set_recv_bps(self, recv_bps):
        self.graph_tracker.add_points(recv_bps_y=recv_bps)


    def _set_sent_bps(self, sent_bps):
        self.graph_tracker.add_points(sent_bps_y=sent_bps)



class DeviceSensorRealTimeRequest(Request):

    def __init__(self, username, password, hostname, device_sensor_module):
        self.device_sensor_module = device_sensor_module
        self.hostname = hostname

        device_sensor_request = dict()
        device_sensor_request['device_sensor_type'] = 'REAL_TIME_REQUEST'
        device_sensor_request['device_sensor_body'] = dict()
        device_sensor_request['agent_hostname'] = hostname

        Request.__init__(self, username, password, device_sensor_request,
                            'DeviceSensor')



class DeviceSensorRealTimeClose(Request):

    def __init__(self, username, password, hostname, original_req_id):

        close_request_body = dict()
        close_request_body['req_id'] = original_req_id

        device_sensor_request = dict()

        device_sensor_request['device_sensor_type'] = 'REAL_TIME_CLOSE'
        device_sensor_request['device_sensor_body'] = close_request_body
        device_sensor_request['agent_hostname'] = hostname

        Request.__init__(self, username, password, device_sensor_request,
                            'DeviceSensor')



class GraphTracker(Thread):

    update_time = 1.0

    def __init__(self, cpu_chart, ram_chart, sent_bps_chart, recv_bps_chart,
                 time_interval):
        Thread.__init__(self)
        self.daemon = True
        self.cpu_chart = cpu_chart
        self.ram_chart = ram_chart
        self.sent_bps_chart = sent_bps_chart
        self.recv_bps_chart = recv_bps_chart

        self.cpu_graph = None
        self.ram_graph = None
        self.sent_bps_graph = None
        self.recv_bps_graph = None

        self.data_lock = Lock()

        self.should_shutdown = False
        self.shutdown_lock = Lock()

        self.cpu_points = GraphPointQueue(time_interval)
        self.ram_points = GraphPointQueue(time_interval)
        self.sent_bps_points = GraphPointQueue(time_interval)
        self.recv_bps_points = GraphPointQueue(time_interval)


    def add_points(self, ram_y=None, cpu_y=None, sent_bps_y=None,
                   recv_bps_y=None):
        self.data_lock.acquire()
        if ram_y is not None:
            self.ram_points.add_point(ram_y)
        if cpu_y is not None:
            self.cpu_points.add_point(cpu_y)
        if sent_bps_y is not None:
            self.sent_bps_points.add_point(sent_bps_y)
        if recv_bps_y is not None:
            self.recv_bps_points.add_point(recv_bps_y)
        self.data_lock.release()


    def shutdown(self):
        self.shutdown_lock.acquire()
        self.should_shutdown = True
        self.shutdown_lock.release()


    def _clear_graphs(self):
        if self.cpu_graph is not None:
            gobject.idle_add(self.cpu_chart.remove_graph, 'cpu')
        if self.ram_graph is not None:
            gobject.idle_add(self.ram_chart.remove_graph, 'ram')
            
        if self.sent_bps_graph is not None:
            sent_has_items = len(self.sent_bps_graph.get_data()) > 1
            if sent_has_items:
                gobject.idle_add(self.sent_bps_chart.remove_graph,
                                 'sent_bps')

        if self.recv_bps_graph is not None:
            recv_has_items = len(self.recv_bps_graph.get_data()) > 1
            if recv_has_items:
                gobject.idle_add(self.recv_bps_chart.remove_graph,
                                 'recv_bps')


    def _build_graphs(self):
        # Build the graphs
        self.cpu_graph = line_chart.Graph('cpu', 'CPU Percent',
                                          self.cpu_points.get_points())
        self.cpu_graph.set_show_title(False)
        self.cpu_graph.set_color([1, 0, 0])
        self.ram_graph = line_chart.Graph('ram', 'RAM Percent',
                                          self.ram_points.get_points())
        self.ram_graph.set_show_title(False)
        self.ram_graph.set_color([1, 0, 0])
        self.sent_bps_graph = line_chart.Graph('sent_bps', 'Sent Bytes',
                                               self.sent_bps_points.get_points())
        self.sent_bps_graph.set_show_title(False)
        self.sent_bps_graph.set_color([1, 0, 0])
        self.recv_bps_graph = line_chart.Graph('recv_bps', 'Recv Bytes',
                                               self.recv_bps_points.get_points())
        self.recv_bps_graph.set_show_title(False)
        self.recv_bps_graph.set_color([1, 0, 0])


    def _add_graphs(self):
        gobject.idle_add(self.cpu_chart.add_graph,
                         self.cpu_graph)
        gobject.idle_add(self.cpu_chart.queue_draw)
        gobject.idle_add(self.ram_chart.add_graph,
                         self.ram_graph)
        gobject.idle_add(self.ram_chart.queue_draw)

        recv_has_items = len(self.recv_bps_graph.get_data()) > 1
        if recv_has_items:
            gobject.idle_add(self.recv_bps_chart.set_yrange, line_chart.RANGE_AUTO)
            gobject.idle_add(self.recv_bps_chart.add_graph,
                             self.recv_bps_graph)
            gobject.idle_add(self.recv_bps_chart.queue_draw)
        else:
            gobject.idle_add(self.recv_bps_chart.set_yrange, [0, 1000])

        sent_has_items = len(self.sent_bps_graph.get_data()) > 1
        
        if sent_has_items:
            gobject.idle_add(self.sent_bps_chart.set_yrange, line_chart.RANGE_AUTO)
            gobject.idle_add(self.sent_bps_chart.add_graph,
                             self.sent_bps_graph)
            gobject.idle_add(self.sent_bps_chart.queue_draw)
        else:
            gobject.idle_add(self.sent_bps_chart.set_yrange, [0, 1000])



        gobject.idle_add(self.sent_bps_chart.set_yrange, line_chart.RANGE_AUTO)


    def run(self):

        while True:
            self.shutdown_lock.acquire()
            if self.should_shutdown:
                self.shutdown_lock.release()
                break
            self.shutdown_lock.release()

            self.data_lock.acquire()
            self._clear_graphs()
            self._build_graphs()
            self._add_graphs()
            self.data_lock.release()

            time.sleep(self.update_time)



class GraphPointQueue:
    """
    Used to keep only the points in the last time_interval seconds.
    """

    def __init__(self, time_interval):
        self.time_interval = time_interval

        self.points = list()


    def _clear(self):
        current_time = time.time()
        for point in self.points:
            point_x, point_y = point
            if point_x < current_time - self.time_interval:
                self.points.remove(point)


    def add_point(self, point_y):
        point_x = time.time()
        self.points.append((point_x, point_y))

        # Clear points which are too old
        self._clear()


    def get_points(self, normalize=True):
        # Clear points which are too old
        self._clear()
        
        if normalize:
            normalized_points = []
            if len(self.points) > 0:
                first_point_x, first_point_y = self.points[0]
                first_time = first_point_x
                for point in self.points:
                    point_x, point_y = point
                    normalized_points.append((point_x - first_time, point_y))
            return normalized_points

        return self.points