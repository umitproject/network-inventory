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

from umit.inventory.server.Configs import ServerConfig

from twisted.internet.protocol import ServerFactory
import twisted.internet.protocol


class ServerModule:
    """The interface for a generic ServerModule."""

    def __init__(self, configs, shell):
        self.configs = configs
        self.shell = shell

        # Initialize to default settings
        self.options = dict()
        self.init_default_settings()

        # Get the options from the configs and save them
        module_options = self.configs.items(self.get_name())
        for option in module_options:
            self.options[option[0]] = option[1]


    def get_name(self):
        """
        Returns the name of the Module.
        Must be implemented.
        """
        raise ServerModule.NotImplemented('get_name')


    def get_protocol_name(self):
        """
        Return the name of the protocol used for this Listening Module.
        See umit.inventory.server.Notification.
        Must be implemented.
        """
        raise ServerModule.NotImplemented('get_protocol_name')


    def init_default_settings(self):
        """
        Sets in the self.options dictionary the default settings for this
        module.
        Should be implemented.
        """
        pass


    class NotImplemented(Exception):

        def __init__(self, name):
            self.err_msg = "Method " + str(name) + "() must be implemented!"

        def __str__(self):
            return repr(self.err_msg)



class ListenerServerModule(ServerModule):
    """ The interface for a ServerModule which listens for notifications"""

    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)


    def listen(self):
        """
        Called when the module must start listening.

        The Module must call listenUDP/listenTCP/listenSSL on the default
        twisted reactor for all ports he wants to listen to.
        Should be implemented.
        """
        pass

