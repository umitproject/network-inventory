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

import os
import gtk
import gobject

from umit.inventory.gui.Configs import NIConfig
from umit.inventory.gui.EventsViewManager import EventsViewManager
from umit.inventory.gui.HostsViewManager import HostsViewManager
from umit.inventory.gui.EventWindowManager import EventWindowManager
from umit.inventory.gui.ReportsHostsView import ReportsHostsView
from umit.inventory.gui.SearchWindowManager import SearchWindowManager
from umit.inventory.gui.HostSelectManager import HostSelectManager
from umit.inventory.gui.ConfigurationWindowManager\
        import ConfigurationWindowManager
from umit.inventory.version import VERSION
from umit.inventory.paths import GLADE_DIR, ICONS_DIR, PIXMAPS_DIR

# TODO needs refactoring
glade_files_path = os.path.join('umit', 'inventory', 'gui', 'glade_files')
ni_main_window_file = os.path.join(glade_files_path, 'ni_main.glade')
ni_auth_window_file = os.path.join(glade_files_path, 'ni_auth_window.glade')
ni_events_view_file = os.path.join(glade_files_path, 'ni_events_view.glade')
ni_event_window_file = os.path.join(glade_files_path, 'ni_event_window.glade')
ni_search_window_file = os.path.join(glade_files_path, 'ni_search_window.glade')
ni_time_date_picker_file = os.path.join(glade_files_path,
                                        'ni_time_date_picker.glade')
ni_search_results_window = os.path.join(glade_files_path,
                                        'ni_search_results_window.glade')
ni_hosts_view_file = os.path.join(glade_files_path, 'ni_hosts_view.glade')
ni_reports_hosts_view = os.path.join(glade_files_path,
                                     'ni_reports_hosts_view.glade')
ni_host_select_file = os.path.join(glade_files_path, 'ni_host_select.glade')
ni_config_window_file = os.path.join(glade_files_path,
                                     'ni_config_window.glade')
ni_server_config_file = os.path.join(glade_files_path,
                                     'ni_server_config.glade')
ni_email_config_file = os.path.join(glade_files_path,
                                    'ni_email_config.glade')
ni_agent_config_file = os.path.join(glade_files_path,
                                    'ni_agents_config.glade')
ni_device_sensor_host_view = os.path.join(glade_files_path,
                                          'ni_device_sensor_host_view.glade')


class NIUIManager(gobject.GObject):
    __gsignals__ = {
        # Emitted when there is a GUI event which should shutdown
        # the Network Inventory GUI
        "shutdown": (gobject.SIGNAL_RUN_FIRST,
                     gobject.TYPE_NONE,
                     ()),
        # Emitted when the user enters valid arguments in the login window
        # Parameters: username, password, host, port, ssl_enabled
        "login": (gobject.SIGNAL_RUN_FIRST,
                  gobject.TYPE_NONE,
                  (str, str, str, int, bool)),
        # Emitted when the user wants to subscribe with the given options.
        # Parameters: protocol, hosts (list), types (list)
        "subscribe": (gobject.SIGNAL_RUN_FIRST,
                      gobject.TYPE_NONE,
                      (str, gobject.TYPE_PYOBJECT, gobject.TYPE_PYOBJECT)),
        # Emitted when the user wants to unsubscribe.
        "unsubscribe": (gobject.SIGNAL_RUN_FIRST,
                        gobject.TYPE_NONE,
                        ()),
        # Emitted when the we are asking for a module specific widget to
        # display event details
        # Parameters: notification object, gtk.Container to add the widget,
        #             gtk.Label to put the module name
        "show-event-details": (gobject.SIGNAL_RUN_FIRST,
                               gobject.TYPE_NONE,
                               (gobject.TYPE_PYOBJECT, gobject.TYPE_OBJECT,
                                gobject.TYPE_OBJECT)),
        }

    glade_files = {
        'main' : ni_main_window_file,#
        'auth' : ni_auth_window_file,#
        'events_view' : ni_events_view_file,#
        'event_window' : ni_event_window_file,#
        'search_window' : ni_search_window_file,
        'time_picker' : ni_time_date_picker_file,
        'search_results' : ni_search_results_window,
        'hosts_view' : ni_hosts_view_file,
        'reports_hosts' : ni_reports_hosts_view,
        'host_select' : ni_host_select_file,
        'config_window' : ni_config_window_file,
        'server_config' : ni_server_config_file,
        'email_config' : ni_email_config_file,
        'agent_config' : ni_agent_config_file,
        'device_sensor_hosts' : ni_device_sensor_host_view,
    }


    def __init__(self, core, conf):
        gobject.GObject.__init__(self)
        self.core = core
        self.shell = core.shell
        self.conf = conf
        self.data_dir = core.data_dir

        self.logged_in = False

        self.hosts = None
        self.ips = None
        self.protocols = None
        
        # Basic widgets initialization
        self.main_window = None
        self.auth_window = None
        self.events_view = None
        self.event_window = None
        self.init_main_window()
        self.init_auth_window()
        self.init_events_view()
        self.init_hosts_view()
        self.init_event_window()

        self.search_window_manager = SearchWindowManager(self)
        self.config_window_manager = ConfigurationWindowManager(self)


    def get_glade_file_path(self, file_name):
        """
        Returns the complete path of the glade file given it's name.
        """
        return os.path.join(self.data_dir, GLADE_DIR, file_name)


    def get_pixmap_file_path(self, file_name):
        """
        Returns the complete path of the pixmap file given it's name.
        """
        return os.path.join(self.data_dir, PIXMAPS_DIR, file_name)


    def get_icon_file_path(self, icon_name):
        """
        Returns the complete path of the icon given it's name.
        """
        return os.path.join(self.data_dir, ICONS_DIR, icon_name)
    

    def init_main_window(self):
        builder = gtk.Builder()
        builder.add_from_file(self.get_glade_file_path('ni_main.glade'))
        self.main_window = builder.get_object('ni_main_window')
        self.main_window.set_icon_from_file(
            self.get_pixmap_file_path('umit_48x48.png'))

        self.ni_notebook = builder.get_object('ni_notebook')
        self.ni_toolbar = builder.get_object('ni_toolbar')
        self.ni_statusbar = builder.get_object('ni_statusbar')
        self.ni_menubar = builder.get_object('ni_menubar')
        self.main_window_builder = builder
        
        self.ni_notebook.remove_page(2)
        self.ni_notebook.remove_page(1)
        self.ni_notebook.remove_page(0)

        self.main_window.connect('destroy', self.on_main_window_destroyed)


    def init_auth_window(self):
        builder = gtk.Builder()
        builder.add_from_file(self.get_glade_file_path('ni_auth_window.glade'))
        self.auth_window = builder.get_object('auth_window')
        self.auth_window.set_icon_from_file(
            self.get_pixmap_file_path('umit_48x48.png'))
        
        # Get the widgets
        self.aw_close_button = builder.get_object('close_button')
        self.aw_login_button = builder.get_object('login_button')
        self.username_te = builder.get_object('username_te')
        self.password_te = builder.get_object('password_te')
        self.host_te = builder.get_object('host_te')
        self.port_te = builder.get_object('port_te')
        self.auth_header_image = builder.get_object('auth_header_image')
        self.auth_header_image.set_from_file(
            self.get_pixmap_file_path('ni_auth_header.png'))
        self.enable_encryption_cb = builder.get_object('enable_encryption_cb')

        # Connect the handlers
        self.aw_close_button.connect('clicked',
                                     self.on_auth_window_close_button_clicked)
        self.aw_login_button.connect('clicked',
                                     self.on_auth_window_login_button_clicked)
        self.auth_window.connect('destroy', self.on_auth_window_destroyed)

        # Initialize the text entries if configured
        self.init_auth_window_text_entries()


    def show_auth_state_error(self, error_msg, error_second_title):
        error_dialog = gtk.MessageDialog(parent=self.auth_window,
                                         type=gtk.MESSAGE_ERROR,
                                         flags=gtk.DIALOG_MODAL,
                                         buttons=gtk.BUTTONS_OK)
        error_dialog.set_property('text', error_second_title)
        error_dialog.set_title('Authentication Error')
        error_dialog.set_property('secondary-text', error_msg)
        error_dialog.connect('response', self.on_dialog_response, False)
        error_dialog.show()


    def show_run_state_error(self, error_msg, error_second_title, fatal=False):
        error_dialog = gtk.MessageDialog(parent=self.main_window,
                                         type=gtk.MESSAGE_ERROR,
                                         buttons=gtk.BUTTONS_OK)
        error_dialog.set_property('text', error_second_title)
        error_dialog.set_title('Runtime Error')
        error_dialog.set_property('secondary-text', error_msg)
        error_dialog.connect('response', self.on_dialog_response, fatal)
        error_dialog.show()


    def on_dialog_response(self, dialog, response_id, fatal):
        dialog.destroy()
        if fatal:
            gtk.main_quit()


    def init_auth_window_text_entries(self):
        username = self.conf.get_general_option(NIConfig.ni_server_username)
        if username is not None:
            self.username_te.set_text(username)

        host = self.conf.get_general_option(NIConfig.ni_server_host)
        if host is not None:
            self.host_te.set_text(host)

        port = self.conf.get_general_option(NIConfig.ni_server_port)
        if port is not None:
            self.port_te.set_text(port)

        ssl_enabled = self.conf.get_general_option(NIConfig.ni_server_enable_ssl)
        if ssl_enabled is not None:
            try:
                ssl_enabled_bool = bool(ssl_enabled)
            except:
                ssl_enabled_bool = True
            self.enable_encryption_cb.set_active(ssl_enabled_bool)
        else:
            self.enable_encryption_cb.set_active(True)


    def validate_auth_window(self):

        # Find the missing fields
        missing_fields = []
        username = self.username_te.get_text()
        if len(username) is 0:
            missing_fields.append('Username')
        password = self.password_te.get_text()
        if len(password) is 0:
            missing_fields.append('Password')
        host = self.host_te.get_text()
        if len(host) is 0:
            missing_fields.append('Host')
        port = self.port_te.get_text()
        if len(port) is 0:
            missing_fields.append('Port')

        # We found some missing fields
        error_secondary_title = None
        error_msg = None
        if len(missing_fields) > 0:
            error_secondary_title = 'Incomplete form'
            error_msg = 'The following fields are missing:\n'
            for missing_field in missing_fields:
                error_msg += ' - %s \n' % missing_field
            self.show_auth_state_error(error_msg, error_secondary_title)
            return False

        # Make sure the port number is an integer
        try:
            port_int = int(port)
        except:
            error_secondary_title = 'Invalid type'
            error_msg = 'The Port field requires a valid integer port number'
            self.show_auth_state_error(error_msg, error_secondary_title)
            return False

        return True


    def init_events_view(self):
        builder = gtk.Builder()
        builder.add_from_file(self.get_glade_file_path('ni_events_view.glade'))
        self.events_view_manager = EventsViewManager(builder, self)
        self.events_view = builder.get_object('events_view_top')
        self.events_view.unparent()
        self.ni_notebook.insert_page(self.events_view,
                                     gtk.Label('Network Events'), 0)


    def init_hosts_view(self):
        builder = gtk.Builder()
        builder.add_from_file(self.get_glade_file_path('ni_hosts_view.glade'))
        self.hosts_view_manager = HostsViewManager(builder, self)
        self.hosts_view = builder.get_object('hosts_view_top')
        self.hosts_view.unparent()
        self.ni_notebook.insert_page(self.hosts_view,
                                     gtk.Label('Network Hosts'), 1)
        self.hosts_view_manager.add_host_detail_view(ReportsHostsView(self))

        # Init the host select
        self.host_select_manager = HostSelectManager(self)
        


    def init_event_window(self):
        ni_event_window_file = self.get_glade_file_path('ni_event_window.glade')
        self.event_window_manager =\
                EventWindowManager(ni_event_window_file, self)


    def init_toolbar(self):
        # Add the configuration button
        # TODO: Test permissions
        self.config_button = gtk.ToolButton(gtk.STOCK_PREFERENCES)
        self.config_button.connect('clicked', self.on_config_clicked)
        self.config_button.set_label('Settings')
        self.ni_toolbar.insert(self.config_button, -1)
        self.config_button.set_sensitive(False)
        self.config_button.show()

        # Add the search events button
        self.search_button = gtk.ToolButton(gtk.STOCK_FIND)
        self.search_button.connect('clicked', self.on_search_events_clicked)
        self.search_button.set_label('Find Events')
        self.ni_toolbar.insert(self.search_button, -1)
        self.search_button.show()

        # Add the host info button
        self.host_info_button = gtk.ToolButton(gtk.STOCK_NETWORK)
        self.host_info_button.connect('clicked', self.on_host_info_clicked)
        self.host_info_button.set_label('Host Info')
        self.ni_toolbar.insert(self.host_info_button, -1)
        self.host_info_button.show()
        self.host_info_button.set_sensitive(False)


    def init_menubar(self):
        # Get the menu bar items
        self.inventory_menuitem =\
            self.main_window_builder.get_object('inventory_menuitem')
        self.edit_menuitem =\
            self.main_window_builder.get_object('edit_menuitem')
        self.view_menuitem =\
            self.main_window_builder.get_object('view_menuitem')
        self.help_menuitem =\
            self.main_window_builder.get_object('help_menuitem')
        self.help_menu =\
            self.main_window_builder.get_object('help_menu')
        self.about_menuitem=\
            self.main_window_builder.get_object('about_menuitem')

        self._init_inventory_menu()
        self._init_edit_menu()
        self._init_view_menu()
        self._init_help_menu()


    def _init_inventory_menu(self):
        # Initialize the inventory menu
        self.inventory_menu = gtk.Menu()
        self.inventory_menuitem.set_submenu(self.inventory_menu)
        self.inventory_menu.show()

        settings_menuitem = gtk.ImageMenuItem(stock_id=gtk.STOCK_PREFERENCES)
        settings_menuitem.set_label('Settings')
        settings_menuitem.show()
        settings_menuitem.connect('activate', self.on_settings_menuitem_activated)
        self.inventory_menu.append(settings_menuitem)

        separator = gtk.SeparatorMenuItem()
        self.inventory_menu.append(separator)
        separator.show()

        quit_menuitem = gtk.ImageMenuItem(stock_id=gtk.STOCK_QUIT)
        quit_menuitem.connect('activate', self.on_quit_menuitem_activated)
        quit_menuitem.show()
        self.inventory_menu.append(quit_menuitem)


    def _init_edit_menu(self):
        # Initialize the edit menu
        self.edit_menu = gtk.Menu()
        self.edit_menuitem.set_submenu(self.edit_menu)
        self.edit_menu.show()

        search_events_menuitem = gtk.ImageMenuItem(stock_id=gtk.STOCK_FIND)
        search_events_menuitem.set_label('Find Events ...')
        search_events_menuitem.connect('activate',
                self.on_search_events_menuitem_activated)
        search_events_menuitem.show()
        self.edit_menu.append(search_events_menuitem)

        separator = gtk.SeparatorMenuItem()
        self.edit_menu.append(separator)
        separator.show()

        receive_events_menuitem = gtk.CheckMenuItem()
        receive_events_menuitem.set_active(True)
        receive_events_menuitem.set_label('Receive Events')
        receive_events_menuitem.connect('toggled',
                self.on_receive_events_menuitem_toggled)
        self.edit_menu.append(receive_events_menuitem)
        receive_events_menuitem.show()
        self.receive_events_menuitem = receive_events_menuitem
        # Connect so we can change the state of the menu item
        self.events_view_manager.receive_events_button.connect('toggled',
            self.on_receive_events_button_toggled)


    def _init_view_menu(self):
        # Initialize the view menu
        self.view_menu = gtk.Menu()
        self.view_menuitem.set_submenu(self.view_menu)
        self.view_menu.show()

        events_tab_menuitem = gtk.MenuItem()
        events_tab_menuitem.set_label('Network Events')
        events_tab_menuitem.show()
        events_tab_menuitem.connect('activate',
                self.on_events_tab_menuitem_activated)
        self.view_menu.append(events_tab_menuitem)

        hosts_tab_menuitem = gtk.MenuItem()
        hosts_tab_menuitem.set_label('Network Hosts')
        hosts_tab_menuitem.show()
        hosts_tab_menuitem.connect('activate',
                self.on_hosts_tab_menuitem_activated)
        self.view_menu.append(hosts_tab_menuitem)

        separator = gtk.SeparatorMenuItem()
        self.view_menu.append(separator)
        separator.show()

        show_host_menuitem = gtk.ImageMenuItem(stock_id=gtk.STOCK_NETWORK)
        show_host_menuitem.set_label('Host Information')
        show_host_menuitem.show()
        show_host_menuitem.connect('activate',
                self.on_show_host_menuitem_activated)
        self.view_menu.append(show_host_menuitem)

    def _init_help_menu(self):
        # Initialize the about dialog
        self.about_menuitem.connect('activate', self.on_about_menuitem_activated)


    def event_show_request(self, notification, parent_window):
        if self.event_window_manager is not None:
            self.event_window_manager.show_event(notification, parent_window)
            cont = self.event_window_manager.get_module_container()
            label = self.event_window_manager.get_module_label()
            self.emit('show-event-details', notification, cont, label)


    def set_login_state(self):
        """ Only shows the authentication window """
        self.auth_window.show()


    def set_run_state(self):
        """ Application running in full mode (after login) """
        self.logged_in = True
        self.auth_window.destroy()

        self.init_toolbar()
        self.init_menubar()
        self.main_window.show()


    def add_events_view_notification(self, notification):
        """ Shows the notification in the Events Tree View """
        self.events_view_manager.add_notification(notification)


    def set_protocols(self, protocols):
        """ Sets the protocols that will be shown in the GUI """
        self.protocols = protocols
        self.events_view_manager.set_protocols(protocols)
        self.search_window_manager.set_protocols(protocols)


    def set_hostnames(self, hostnames):
        """ Sets the hostnames that will be shown in the GUI """
        self.hosts = hostnames
        self.events_view_manager.set_hosts(hostnames)
        self.hosts_view_manager.set_hosts(hostnames)
        self.search_window_manager.set_hosts(hostnames)

        # Make the host select button sensitive
        self.host_info_button.set_sensitive(True)


    def enable_configurations(self):
        """ Called when the config editing options should be sensitive """
        self.config_button.set_sensitive(True)


    def set_ips(self, ips):
        """ Sets the IP addresses that will be shown in the GUI """
        self.ips = ips
        self.events_view_manager.set_ips(ips)
        self.hosts_view_manager.set_ips(ips)
        self.search_window_manager.set_ips(ips)


    def search_events(self):
        if not self.search_window_manager.window_is_shown():
            self.search_window_manager.show_window(self.main_window)


    # Login state handlers

    def on_auth_window_close_button_clicked(self, button):
        self.emit('shutdown')


    def on_auth_window_login_button_clicked(self, button):
        if self.validate_auth_window():
            username = self.username_te.get_text()
            password = self.password_te.get_text()
            host = self.host_te.get_text()
            port = int(self.port_te.get_text())
            enable_ssl = self.enable_encryption_cb.get_active()
            self.emit('login', username, password, host, port, enable_ssl)


    def on_auth_window_destroyed(self, auth_window):
        if not self.logged_in:
            self.emit('shutdown')


    def on_main_window_destroyed(self, main_window):
        self.emit('shutdown')


    # Run state handlers

    def on_config_clicked(self, config_button):
        self.config_window_manager.show()


    def on_search_events_clicked(self, search_button):
        self.search_events()


    def on_host_info_clicked(self, host_info_button):
        self.host_select_manager.show(self.main_window, self.hosts)

        
    def on_about_menuitem_activated(self, menuitem_activated):
        about_dialog = gtk.AboutDialog()
        about_dialog.set_name('Umit Project')
        about_dialog.set_program_name('Umit Network Inventory')
        about_dialog.set_version(VERSION)
        about_dialog.set_authors(['Dragos Dena'])
        about_dialog.set_copyright('Copyright (C) 2011 Adriano Monteiro Marques')
        logo_path = self.get_pixmap_file_path('about_ni_image.png')
        logo_pixbuf = gtk.gdk.pixbuf_new_from_file(logo_path)
        icon_path = self.get_icon_file_path('umit_48.ico')
        about_dialog.set_icon_from_file(icon_path)
        about_dialog.set_logo(logo_pixbuf)
        about_dialog.set_website('http://www.umitproject.org')
        about_dialog.connect('response', self.on_dialog_response, False)
        about_dialog.show()


    def on_settings_menuitem_activated(self, settings_menuitem):
        self.config_window_manager.show()


    def on_quit_menuitem_activated(self, quit_menuitem):
        gtk.main_quit()


    def on_search_events_menuitem_activated(self, search_events_menuitem):
        self.search_events()


    def on_receive_events_menuitem_toggled(self, receive_events_menuitem):
        self.events_view_manager.set_receive_events(
            receive_events_menuitem.get_active())


    def on_receive_events_button_toggled(self, button):
        self.receive_events_menuitem.set_active(button.get_active())


    def on_events_tab_menuitem_activated(self, events_tab_menuitem):
        self.ni_notebook.set_current_page(0)


    def on_hosts_tab_menuitem_activated(self, hosts_tab_menuitem):
        self.ni_notebook.set_current_page(1)


    def on_show_host_menuitem_activated(self, show_host_menuitem):
        self.host_select_manager.show(self.main_window, self.hosts)