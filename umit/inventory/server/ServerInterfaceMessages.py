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

import logging
import json


class Request:
    """ Request base class """

    def __init__(self, data, host, port):
        self.data = data
        self.host = host
        self.port = port

        self.request = None

        self.username = None
        self.password = None
        self.target = None
        self.request_id = None
        self.body = None


    def sanity_check(self):
        """
        Must be performed after initialisation.
        Also does the de-serialization of the request.
        """
        # Check it's JSON seriazable
        try:
            request = json.loads(self.data)
            self.request = request
        except:
            err_msg = 'ServerInterface: Received non-JSON serializable request'
            err_msg += ' from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port),\
                            exc_info=True)
            return False

        # Check the username
        try:
            self.username = request[RequestFields.username]
        except:
            err_msg = 'ServerInterface: Missing username in request from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port))
            return False

        # Check the password
        try:
            self.password = request[RequestFields.password]
        except:
            err_msg = 'ServerInterface: Missing password in request from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port))
            return False

        # Check the request id
        try:
            self.request_id = request[RequestFields.request_id]
        except:
            err_msg = 'ServerInterface: Missing request_id in request from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port))
            return False

        # Check the target
        try:
            self.target = request[RequestFields.target]
        except:
            err_msg = 'ServerInterface: Missing target in request from %s:%s'
            logging.warning(err_msg, str(self.host), str(self.port))

        # Check the body (optional)
        if RequestFields.body in request.keys():
            self.body = request[RequestFields.body]

        return True


    # Request fields

    def get_username(self):
        return self.username


    def get_password(self):
        return self.password


    def get_request_id(self):
        return self.request_id


    def get_target(self):
        return self.target


    def get_body(self):
        return self.body



class GeneralRequest:

    def __init__(self, request):
        self.request = request

        self.type = None
        self.body = None


    def sanity_check(self):
        """ Checks the fields. Must be called after initialization """
        # Check the type
        try:
            self.type = self.request.body[GeneralRequestBody.request_type]
        except:
            err_msg = 'ServerInterface: Missing type from general request'
            logging.warning(err_msg)
            return False

        # Check the body (optional)
        if GeneralRequestBody.request_body in self.request.body:
            self.body = self.request.body[GeneralRequestBody.request_body]

        return True


    def get_type(self):
        return self.type


    def get_body(self):
        return self.body



class ConnectGeneralRequest:

    def __init__(self, general_request):
        self.body = general_request.get_body()


    def sanity_check(self):
        try:
            self.encryption_enabled =\
                self.body[ConnectGeneralRequestBody.enable_encryption]
        except:
            err_msg = 'ServerInterface: Missing encrypt_enabled field from'
            err_msg += ' connect request'
            logging.warning(err_msg)
            return False

        return True


    def get_encryption_enabled(self):
        return self.encryption_enabled



class SubscribeGeneralRequest:

    def __init__(self, general_request):
        self.body = general_request.get_body()


    def sanity_check(self):
        try:
            self.protocol = self.body[SubscribeGeneralRequestBody.protocol]
        except:
            err_msg = 'ServerInterface: Missing protocol field from'
            err_msg += ' subscribe request'
            logging.warning(err_msg)
            return False

        try:
            self.hosts = self.body[SubscribeGeneralRequestBody.hosts]
        except:
            err_msg = 'ServerInterface: Missing hosts field from'
            err_msg += ' subscribe request'
            logging.warning(err_msg)
            return False

        try:
            self.types = self.body[SubscribeGeneralRequestBody.types]
        except:
            err_msg = 'ServerInterface: Missing types field from'
            err_msg += ' subscribe request'
            logging.warning(err_msg)
            return False

        return True


    def get_protocol(self):
        return self.protocol


    def get_hosts(self):
        return self.hosts


    def get_types(self):
        return self.types



class SearchGeneralRequest:

    def __init__(self, general_request):
        self.body = general_request.get_body()


    def sanity_check(self):
        try:
            self.spec = self.body[SearchGeneralRequestBody.spec]
        except:
            err_msg = 'ServerInterface: Missing spec field from'
            err_msg += ' search request'
            logging.warning(err_msg)
            return False

        try:
            self.fields = self.body[SearchGeneralRequestBody.fields]
        except:
            err_msg = 'ServerInterface: Missing fields field from'
            err_msg += ' search request'
            logging.warning(err_msg)
            return False

        try:
            self.sort = self.body[SearchGeneralRequestBody.sort]
        except:
            err_msg = 'ServerInterface: Missing sort field from'
            err_msg += ' search request'
            logging.warning(err_msg)
            return False

        return True


    def get_spec(self):
        return self.spec


    def get_fields(self):
        return self.fields


    def get_sort(self):
        return self.sort



class SearchNextGeneralRequest:

    def __init__(self, general_request):
        self.body = general_request.get_body()


    def sanity_check(self):
        try:
            self.search_id = self.body[SearchNextGeneralRequestBody.search_id]
        except:
            err_msg = 'ServerInterface: Missing search_id field from'
            err_msg += ' search request'
            logging.warning(err_msg)
            return False


        try:
            self.start_index =\
                    self.body[SearchNextGeneralRequestBody.start_index]
        except:
            err_msg = 'ServerInterface: Missing start_index field from'
            err_msg += ' search request'
            logging.warning(err_msg)
            return False

        return True


    def get_search_id(self):
        return self.search_id


    def get_start_index(self):
        return self.start_index



class SearchStopGeneralRequest:

    def __init__(self, general_request):
        self.body = general_request.get_body()

    def sanity_check(self):
        try:
            self.search_id = self.body[SearchStopGeneralRequestBody.search_id]
        except:
            err_msg = 'ServerInterface: Missing search_id field from'
            err_msg += ' search request'
            logging.warning(err_msg)
            return False

        return True


    def get_search_id(self):
        return self.search_id



class SetConfigsGeneralRequest:

    def __init__(self, general_request):
        self.body = general_request.get_body()

    def sanity_check(self):
        try:
            self.configs = self.body[SetConfigsGeneralRequestBody.configs]
        except:
            err_msg = 'ServerInterface: Missing configs field from'
            err_msg += ' set_configs request'
            logging.warning(err_msg)
            return False

        # Check it's the correct format
        try:
            print self.configs
            sections = self.configs.keys()
            for section in sections:
                options = self.configs[section].keys()
        except:
            err_msg = 'ServerInterface: configs field has invalid format in'
            err_msg += ' set_configs request'
            logging.warning(err_msg, exc_info=True)
            return False

        return True


    def get_configs(self):
        return self.configs


    
# Requests format section

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
    The mandatory fields in a request having the 'GENERAL' target:
    * request_type: Identifies the type of the general request. This field can
      have one of the following values:
      - "CONNECT": The requesting side wants to connect to the
        Server. This is mandatory before sending any other request. See
        ConnectGeneralRequestBody for details about this request.
      - "SUBSCRIBE": The requesting side wants to subscribe to the Server to
        receive notifications as they come. This will ony forward notifications
        which are not reports. See SubscribeGeneralRequestBody for details
        about this request.
      - "UNSUBSCRIBE": The requesting side wants to stop receiving notifications
        from the Server. There isn't any associated body for this type.
      - "GET_MODULES": The requesting side wants to know which modules are
        installed and enabled on the Server. There isn't any associated body
        for this request.
      - "GET_HOSTS": The requesting side wants to know which host entries are
        in the Server's database. There isn't any associated body for this
        type.
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


class ConnectGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "CONNECT":
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
    * protocol: The protocol for which the server wants to receive
      notifications. If the value is 'All', notifications from all the
      protocols will be sent.
    * hosts: A list of hosts for which the requesting side wants to receive
      notifications. An element of an list can be:
      - An IPv4 address.
      - An IPv6 address.
      - A host name.
      - A network address with it's subnet mask in the form of a string
        (e.g. '192.168.2.0/24')
      If the list is empty, the requesting side wants to receive notifications
      from all the hosts for which he has permissions.
    * types: A list of notification types for which the requesting side wants
      to receive notifications (or an empty list for all the types).

    Note: If a some of the subscription request fields aren't allowed by the
          user permissions, then only notifications that are allowed and
          requested will be sent, discarding the non-allowed requests.
    """
    protocol = 'protocol'
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
    """
    fields = 'fields'
    spec = 'spec'
    sort = 'sort'


class SearchNextGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SEARCH_NEXT":
    * search_id: The Search for which we want to get the next results. This
      must be equal to the search_id in the initial "SEARCH" request.
    * start_index: The start index in the vector of the search results. The
      size of the returned vector will be less or equal with the size of a
      page.
    """
    search_id = 'search_id'
    start_index = 'start_index'


class SearchStopGeneralRequestBody:
    """
    The mandatory fields in a general request having request_type equal to
    "SEARCH_STOP":
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


# Responses format section

class ResponseCodes:
    accepted = 200
    auth_denied = 401
    missing_connection = 403
    missing_permissions = 400
    invalid = 406
    internal_error = 500
    connection_closed = 100


class ResponseFields:
    """
    The mandatory fields in a response:
    * request_id: The request_id of the associated request with this response.
      For asynchronous responses (e.g. notifications) this is -1.
    * response_code: An int showing the state of the response:
      - 200: The request was accepted.
      - 401: Authentication denied.
      - 403: Request without prior to a connection.
      - 400: Missing permissions.
      - 406: Invalid request.
      - 500: Internal error.
      - 100: Connection Closed
    * response_type: A string showing the response type. This is useful only
      for asynchronous response (request_id == -1). For synchronous responses,
      the request_id is sufficient to determine the type of the response.
      For 'SUBSCRIBE' asynchronous responses, this field will be set to
      'SUBSCRIBE_RESPONSE' and the body will contain a list with notifications.
    * body: Based on the request_id which will identify the request type, then
      this will contain the response body. For requests having the 'GENERAL'
      target and based on the 'general_request_type' field, the following
      responses bodies are possible:
      - 'CONNECT': ConnectResponseBody
      - 'GET_MODULES': GetModulesResponseBody
      - 'GET_CONFIGS': GetConfigsResponseBody
      - 'SEARCH': SearchResponseBody
      - 'SEARCH_NEXT': SearchResponseBody
      - 'GET_USERS': GetUsersResponseBody

    Note: The body field is present only if response_code is equal 200.
    """
    request_id = 'request_id'
    response_code = 'response_code'
    response_type = 'response_type'
    body = 'body'


class ConnectResponseBody:
    """
    The response for a 'CONNECT' general request. Fields:
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
    * protocols: A list with the listening protocols present on the server.
    """
    permissions = 'permissions'
    data_port = 'data_port'
    encryption_enabled = 'encryption_enabled'
    token = 'token'
    protocols = 'protocols'


class GetModulesResponseBody:
    """
    The response for a 'GET_MODULES' general request. Fields:
    * modules: A list with the modules installed and enabled on the server.
    """
    modules = 'modules'


class GetHostsResponseBody:
    """
    The respose for a 'GET_HOSTS' general request. Fields:
    * hostnames: A list with the hostnames for the hosts in the database.
    * ipv4_addresses: A list with the IPv4 addresses for the hosts in the
      database.
    * ipv6_addresses: A list with the IPv6 addresses for the hosts in the
      database.

    Note: hostnames[i], ipv4_addresses[i] and ipv6_addresses[i] reffer to
    information about the same host (the i'th one in the database).
    """
    hostnames = 'hostnames'
    ipv4_addresses = 'ipv4_addresses'
    ipv6_addresses = 'ipv6_addresses'


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
    * total_results_count: An integer representing the total results count.
    * search_id: An integer that must be used to get the next search results
      or stop the search. It identifies searches on the server side.
    """
    results = 'results'
    total_results_count = 'total_results_count'
    search_id = 'search_id'


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