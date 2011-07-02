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

from OpenSSL import crypto

from umit.inventory.server.Notification import Notification
from umit.inventory.server.Notification import NotificationFields
from umit.inventory.server.Configs import ServerConfig

from twisted.internet import reactor
from twisted.internet import ssl
from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
from twisted.internet.address import IPv4Address

import socket
import logging
import json
import tempfile
from copy import copy
import os
import hashlib


class ServerInterface:
    """ Provides an interface to access the local data to GUI applications """

    # SSL certificate expiration: 10 years
    cert_expire = 316224000

    # SSL files
    cert_file_name = os.path.join(tempfile.gettempdir(),\
                                  'umit_server_interface.cert')
    key_file_name = os.path.join(tempfile.gettempdir(),\
                                 'umit_server_interface.key')


    def __init__(self, conf, user_system, shell):
        self.user_system = user_system
        self.conf = conf
        self.shell = shell
        self.requests_port =\
                self.conf.get_general_option(ServerConfig.interface_port)



    def _generate_ssl_files(self):
        # Certificate and key files only for this session
        key_file = open(self.key_file_name, 'w')
        cert_file = open(self.cert_file_name, 'w')

        # Generate the key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 1024)

        # Generate the certificate
        cert = crypto.X509()
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(ServerInterface.cert_expire)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha1')

        # Write to files
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        key_file.close()
        cert_file.close()


    def get_connection(self, request):
        """
        Gets the connection for this request, or None if an 'AUTHENTICATE'
        request was not sent prior to this one.
        """
        # TODO
        return None


    def evaluate_general_request(self, request):
        # TODO
        pass


    def receive_request(self, data, host, port):
        """ Called when a request is received """
        # De-serialize the request
        try:
            request = json.loads(data)
        except:
            err_msg = 'ServerInterface: Received non-JSON serializable request'
            err_msg += ' from %s:%s' % (str(host), str(port))
            logging.warning(err_msg, exc_info=True)
            return

        # Check username and password for the request
        try:
            username = request[RequestFields.username]
        except:
            err_msg = 'ServerInterface: Missing username in request from %s:%s'
            logging.warning(err_msg, str(host), str(port))
            return
        try:
            password = request[RequestFields.password]
        except:
            err_msg = 'ServerInterface: Missing password in request from %s:%s'
            logging.warning(err_msg, str(host), str(port))
            return

        try:
            self.user_system.validate_user(username, password)
        except:
            logging.error('ServerInterface: Authentication failure from %s:%s',\
                          str(host), str(port), exc_info=True)
            return

        # Make sure we have the target field
        try:
            target = request[RequestFields.target]
        except:
            err_msg = 'ServerInterface: Missing target in request from %s:%s'
            logging.warning(err_msg, str(host), str(port))

        # Check the target of the request
        if target == "GENERAL":
            # General request
            self.evaluate_general_request(request)
        else:
            # Module specific request

            # Get the connection for this request
            connection = self.get_connection(request)
            if connection is None:
                err_msg = 'ServerInterface: Received request prior to an '
                err_msg += 'AUTHENTICATION request from %s:%s'
                logging.error(err_msg, str(host), str(port))
                return

            # Check if the targeted module exists
            modules_names = self.shell.get_modules_names_list()
            if target not in modules_names:
                err_msg = 'ServerInterface: Invalid Request target %s from '
                err_msg += '%s:%s' % (str(host), str(port))
                logging.error(err_msg)
                return

            # Forward the request to the module
            module = self.shell.get_module(target)
            module.evaluate_request(request, connection)


    def listen(self):
        """ Called when we should start listening to requests """
        ssl_factory = Factory()
        ServerInterfaceSSLProtocol.agent_listener = self
        ssl_factory.protocol = ServerInterfaceSSLProtocol
        ssl_context_factory = ssl.DefaultOpenSSLContextFactory(\
            self.key_file_name, self.cert_file_name)
        logging.info('ServerInterface: Trying to listen SSL on port %s',\
                     str(self.requests_port))
        try:
            reactor.listenSSL(self.requests_port, ssl_factory, ssl_context_factory)
            logging.info('ServerInterface: Listening SSL on port %s',\
                         str(self.requests_port))
        except:
            logging.error('ServerInterface: Failed to listen SSL on port %s',\
                          str(self.requests_port))



class ServerInterfaceSSLProtocol(Protocol):
    """ Listening for requests """

    # The ServerInterface object
    server_interface = None

    def __init__(self):
        self.server_interface = ServerInterfaceSSLProtocol.server_interface

    def dataReceived(self, data):
        peer = self.transport.getPeer()
        host = ''
        port = -1
        if isinstance(peer, IPv4Address):
            # TODO IPv6?
            host = peer.host
            port = peer.port
        self.server_interface.receive_request(host, port, data)

# Requests section

class RequestFields:
    """
    The mandatory fields in a request:
    * username: The username in the Server User System.
    * password: The password associated with the username in the Server User
      System. The username and password will be used to authenticate the user
      and check his permissions.
    * target: The target for the request. Can have one of the following values:
      - General: This is a general request that isn't conditioned by a the
        presence of a particular module.
      - [module_name]: This can be the name of a module (e.g. AgentListener,
        SNMPListener, etc) and the request body will be forwarded to be solved
        to the corresponding module (after authentication is done).
    * request_id: A positive integer identifying the request of the requesting
      side. It's mandatory for the requesting side to guarantee that it doesn't
      have 2 pending requests with the same request_id values. The response to
      the request will also contain the request_id field having the same value.
    * body: The actual body for the request which is dependent on the target
      value. For a 'General' target request, see GeneralRequestBody.
    """
    username = 'username'
    password = 'password'
    target = 'target'
    request_id = 'request_id'
    body = 'body'


class GeneralRequestBody:
    """
    The mandatory fields in a request having the 'General' target:
    * request_type: Identifies the type of the general request. This field can
      have one of the following values:
      - "AUTHENTICATION": The requesting side wants to authenticate to the
        Server. This is mandatory before sending any other request. See
        AuthenticationGeneralRequestBody for details about this request.
      - "SUBSCRIBE": The requesting side wants to subscribe to the Server to
        receive notifications as they come. See SubscribeGeneralRequestBody for
        details about this request.
      - "GET_MODULES": The requesting side wants to know which modules are
        installed and enabled on the Server. There isn't any associated body
        for this request.
      - "GET_CONFIGS": The requesting side wants to get the current
        configurations of the Server. There isn't any associated body for this
        type.
      - "SET_CONFIGS": The requesting side wants to set configurations on the
        Server. See SetConfigsGeneralRequestBody for details about this request.
      - "RESTART": The requesting side wants to restart the Server. There isn't
        any associated body for this type.
      - "SEARCH": The requesting side wants to search the notifications. See
        SearchGeneralRequestBody for details about this request.
      - "SEARCH_NEXT": The requesting side wants to get the next results for a
        search he already requested. See SearchNextGeneralRequestBody for
        details about this request.
      - "SEARCH_STOP": The requesting side wants to end getting results for a
        search. See SearchStopGeneralRequestBody for details about this request.
      - "ADD_USER": The requesting side wants to add a user to the Server User
        System. See AddUserGeneralRequestBody for details about this request.
      - "DEL_USER": The requesting side wants to delete a user from the Server
        User System. See DelUserGeneralRequestBody for details about this
        request.
      - "SET_USER": The requesting side wants to set permissions or a new
        password for a user. See SetUserGeneralRequestBody for details about
        this request.
      - "GET_USERS": The requesting side wants to get the list with all the
        users and their permission. There isn't any associated body for this
        type.
    """
    request_type = 'general_request_type'
    request_body = 'general_request_body'


class AuthenticateGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "AUTHENTICATE":
    * enable_encryption: If True, subsequent request/responses will use a SSL
      encrypted TCP connection. If False, a non-encrypted TCP connection will
      be used. Note: This can be overridden by the Server Configurations. See
      AuthenticationResponseBody.
    """
    enable_encryption = 'enable_encryption'


class SubscribeGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SUBSCRIBE":
    * protocols: A list of protocols for which the requesting side wants to
      receive notifications.
    * hosts: A list of hosts for which the requesting side wants to receive
      notifications. An element of an list can be:
      - An IPv4 address.
      - An IPv6 address.
      - A host name.
      - A network address with it's subnet mask in the form of a string
        (e.g. '192.168.2.0/24')
    * types: A list of notification types for which the requesting side wants
      to receive notifications.

    Note: If a some of the subscription request fields aren't allowed by the
          user permissions, then only notifications that are allowed and
          requested will be sent, discarding the non-allowed requests.
    """
    protocols = 'protocols'
    hosts = 'hosts'
    types = 'types'


class SetConfigsGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SET_CONFIGS":
    * configs: A dictionary with the following structure:
      - At the top level there are entries having as keys the section name
        and as values dictionaries as described next.
      - The dictionary associated with a section have as keys the name of
        the option and as values the option value.

    Note: If the permission don't allow the user to set the configurations,
          then they won't be set.
    """
    configs = 'configs'


class SearchGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SEARCH":
    * fields: A list with the fields names that should be put in the response.
      If this list is empty, then all the fields will be returned.
    * spec: Used to filter the returned results. A dictionary with keys being
      names of the fields and as values lists with the following format:
      [<spec_id>, <spec_param_1>, ..., <spec_param_n>]. The parameters are
      based on the value of the spec_id. A list with the possible spec_id's
      and the corresponding format:
      - ['eq', <value>]: The field must be equal to <value>
      - ['neq', <value>]: The field must not be equal to <value>
      - ['gt', <value>]: The field must be greater than <value>
      - ['lt', <value>]: The field must be less than <value>
      - ['range', <value1>, <value2>]: The field must be greater than <value1>,
        but less than <value2>.
      - ['in', <value_1>, ..., <value_n>]: The field must be in the list
        [<value_1>, ..., <value_n>]
      - ['nin', <value_1>, ..., <value_n>]: The field must not be in the list
        [<value_1>, ..., <value_n>]
    * sort: A list of the fields that should be sorted. The order in which they
      will be considered for sorting will be from the first field in this list
      to the last one. Each entry in the list must be a list of 2 elements:
      [<field_name>, true|false], where the first element tells the name of
      the field to be sorted and the second element is the direction of sorting
      (true for Ascending, false for Descending).
    * search_id: A search id which will be must for getting the next items
      in the returned result.
    """
    fields = 'fields'
    spec = 'spec'
    sort = 'sort'
    search_id = 'search_id'


class SearchNextGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SEARCH_NEXT":
    * search_id: The Search for which we want to get the next results. This
      must be equal to the search_id in the initial "SEARCH" request.
    """
    search_id = 'search_id'


class SearchNextGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SEARCH_NEXT":
    * search_id: The search for which we want to stop getting results. This
      must be equal to the search_id in the initial "SEARCH" request.
    """
    search_id = 'search_id'


class AddUserGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "ADD_USER":
    * username: The name of the user to be added to the Server User System.
    * password: The password for the user to be added to the Server User System.
    * permissions: The permissions for the user. See UserPermissions class in
      umit.inventory.server.UserSystem for details.
    Note: If the requesting user doesn't have the permissions to add an user,
          then the request will be discarded.
    """
    username = 'username'
    password = 'password'


class DelUserGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "DEL_USER":
    * username: The name of the user to be deleted from the Server User System.

    Note: If the requesting user doesn't have the permissions to delete an user,
          then the request will be discarded.
    """
    username = 'username'


class SetUserGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "DEL_USER":
    * username: The name of the user for which we want to set permissions or
      the password.
    * permissions: The new permissions for the user. See UserPermissions class
      in umit.inventory.server.UserSystem for details.
    * set_permissions: If True, then the permissions will be set according to
      the permissions field.
    * password: The new password for the user.
    * set_password. If True, then the password will be set according to the
      password field.
    """
    username = 'username'
    permissions = 'permissions'
    set_permissions = 'set_permissions'
    password = 'password'
    set_password = 'password'


# Responses section

class ResponseFields:
    """
    The mandatory fields in a response:
    * request_id: The request_id of the associated request with this response.
      For asynchronous responses (e.g. notifications) this is -1.
    * response_code: An int showing the state of the response:
      - 200: The request was accepted.
      - 401: Authentication denied.
      - 403: Request without prior authentication.
      - 400: Missing permissions.
      - 406: Invalid request.
    * body: Based on the request_id which will identify the request type, then
      this will contain the response body. For requests having the 'GENERAL'
      target and based on the 'general_request_type' field, the following
      responses bodies are possible:
      - 'AUTHENTICATE': AuthenticateResponseBody
      - 'GET_CONFIGS': GetConfigsResponseBody
      - 'SEARCH': SearchResponseBody
      - 'SEARCH_NEXT': SearchResponseBody
      - 'GET_USERS': GetUsersResponseBody

    Note: The body field is present only if response_code is equal 200.
    """
    request_id = 'request_id'
    response_code = 'response_code'
    body = 'body'


class AuthenticateResponseBody:
    """
    The response for a 'AUTHENTICATE' general request. Fields:
    * permissions: The permissions for the user as they are stored on the
      server. See umit.inventory.server.UserSystem.UserPermissions (the value
      here is what is returned by the serialize method). This field is only
      present if authentication_accepted is True.
    * data_port: The port on the Server side which will forward the data to
      the requesting_side. It's the port used to send all the other responses.
    * encryption_enabled: If the newly opened TCP port uses SSL this is True.
      If the Server is configured to use SSL for the data port, this will be
      True, otherwise it will be equal to the 'enable_encryption' field in
      AuthenticateGeneralRequestBody.
    """
    permissions = 'permissions'
    data_port = 'data_port'
    encryption_enabled = 'encryption_enabled'


class GetConfigsResponseBody:
    """
    The response for a 'GET_CONFIGS' general request. Fields:
    * configs: A dictionary with the following structure:
      - At the top level there are entries having as keys the section name
        and as values dictionaries as described next.
      - The dictionary associated with a section have as keys the name of
        the option and as values the option value.
    """
    configs = 'configs'


class SearchResponseBody:
    """
    The response for a 'SEARCH' and 'SEARCH_NEXT' general requests. Fields:
    * results: A list with the results JSON serialized as it was requested
      in the first 'SEARCH' request.
    * current_position: An integer representing the current start position
      for this list with returned results in all the returned results.
    * total_results_count: An integer representing the total results count.
    """
    results = 'results'
    current_position = 'current_position'
    total_results_count = 'total_results_count'


class GetUsersResponseBody:
    """
    The response for a 'GET_USERS' general request. Fields:
    * users: A list with the user names.
    * permissions: A list with the corresponding permissions for the user
      names in the users list.
      See umit.inventory.server.UserSystem.UserPermissions (the value
      here is what is returned by the serialize method). This field is only
      present if authentication_accepted is True.
    """
    users = 'users'
    permissions = 'permissions'