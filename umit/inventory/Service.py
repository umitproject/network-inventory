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

from os.path import splitext, abspath

import win32serviceutil
import win32service
import win32event
import win32api
import servicemanager


import logging

class UmitService(win32serviceutil.ServiceFramework):

    _svc_name_ = 'umitservice'
    _svc_display_name_ = 'Umit Service'
    _svc_description_ = 'A generic Umit Service'

    _file = __file__
    

    def __init__(self, *args):
        logging.info('Initializing as a service ...')
        win32serviceutil.ServiceFramework.__init__(self, *args)

        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        logging.info('Initialized as a service')
    
    
    def SvcDoRun(self):
        logging.info('Starting as a service ...')
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        
        try:
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            logging.info('Starting service main loop')
            servicemanager.LogInfoMsg('Entering start()')
            self.start()
            servicemanager.LogInfoMsg('Exiting start()')
            logging.info('Finished service main loop')

            logging.info('Waiting for service to stop')
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)

            logging.info('Stopped')
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)
        except:
            logging.error('Error starting as a service', exc_info=True)
            self.stop()


    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        logging.info('Stopping the service ...')

        self.stop()
        logging.info('Set the stop flag')

        # Ensure we don't exit prematurely
        win32event.SetEvent(self.stop_event)


    @staticmethod
    def install(service_class, stay_alive=True):
        logging.info('Installing service ...')
        
        module_file = splitext(abspath(service_class._file))[0]
        service_class._svc_reg_class_ = '%s.%s' % (module_file,
                                                   service_class.__name__)

        if stay_alive:
            win32api.SetConsoleCtrlHandler(lambda x: True, True)

        try:
            win32serviceutil.InstallService(
                    service_class._svc_reg_class_,
                    service_class._svc_name_,
                    service_class._svc_display_name_,
                    startType=win32service.SERVICE_AUTO_START,
                    description=service_class._svc_description_,
                    )
        except:
            logging.info('Installing service failed', exc_info=True)
            raise
        logging.info('Service installed')


    def start(self):
        """
        Should be implemented.
        """
        pass


    def stop(self):
        """
        Should be implemented.
        """
        pass


    @staticmethod
    def start_service(name):
        win32serviceutil.StartService(name)


    @staticmethod
    def stop_service(name):
        win32serviceutil.StopService(name)
