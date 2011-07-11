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

class Host:
    """
    The class used to represent a host. Fields:
    * hostname: The name of the host.
    * ipv4_addr: The IP version 4 address of the host (or '' if not known).
    * ipv6_addr: The IP version 6 address of the host (or '' if not known).
    """
    hostname = 'hostname'
    ipv4_addr = 'ipv4_addr'
    ipv6_addr = 'ipv6_addr'

    def __init__(self, hostname, ipv4_addr='', ipv6_addr=''):
        self.ipv4_addr = ipv4_addr
        self.ipv6_addr = ipv6_addr
        self.hostname = hostname


    def to_db_object(self):
        fields = dict()
        fields[Host.hostname] = self.hostname
        fields[Host.ipv4_addr] = self.ipv4_addr
        fields[Host.ipv6_addr] = self.ipv6_addr
        return fields


    @staticmethod
    def from_db_object(db_fields):
        return Host(db_fields[Host.hostname],\
                    db_fields[Host.ipv4_addr],\
                    db_fields[Host.ipv6_addr])