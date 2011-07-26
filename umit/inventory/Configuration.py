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

from ConfigParser import ConfigParser
import os


class InventoryConfig(ConfigParser):

    # General section options
    general_section = 'GeneralSection'

    # Log path and level
    log_path = 'log_path'
    log_level = 'log_level'
    default_log_level = 'warning'

    # Modules standard options
    module_enabled = 'enabled'
    module_path = 'path'

    # Section option if it's associated with a module
    is_module = 'is_module'


    def __init__(self, config_file_path=None):
        ConfigParser.__init__(self)
        self.config_file_path = config_file_path

        if config_file_path is None:
            self._set_default_config_file()

        if self.config_file_path is None:
            self.load_default_settings()
        else:
            self.load_settings()


    def get_core_modules(self):
        """
        Returns a list with core modules. A core module can't be disabled.

        Should be overwritten.
        """
        return []


    def is_core_module(self, module_name):
        """ Returns True if module_name is a Core module """
        return module_name in self.get_core_modules()


    # File handling methods

    def load_default_settings(self):
        self._clear_settings()
        self._set_default_settings()


    def load_settings(self):
        """
        Loads the settings from the file located at self.config_file_path.
        If that file doesn't exist it will try to create it. If it can't create
        it, then it will raise an InventoryConfig.ConfigFile exception.
        The newly created file will also be filled with the default settings.
        """
        self._set_default_settings()
        if not os.path.isfile(self.config_file_path):
            try:
                config_file = open(self.config_file_path, 'w')
            except:
                raise InventoryConfig.ConfigFile(self.config_file_path)

            self.load_default_settings()
            self.save_settings()
            self.read(self.config_file_path)
        else:
            config_file = open(self.config_file_path)
            self.readfp(config_file)
    

    def save_settings(self):
        """Saves the settings in the file located at self.config_file_path"""
        config_file = open(self.config_file_path, 'w')
        self.write(config_file)


    def get(self, section, option):
        """ Used to ensure boolean sanity """
        if not self.has_option(section, option):
            return None

        value = ConfigParser.get(self, section, option, raw=True)
        if value in ('False', 'false'):
            return False
        return value


    # General options methods

    def set_general_option(self, option_name, option_value):
        """Set an option which will be saved in the GeneralSettings section"""
        self.set(InventoryConfig.general_section, option_name, option_value)


    def get_general_option(self, option_name):
        """Get an option which is saved in the GeneralSettings section"""
        if self.has_option(InventoryConfig.general_section, option_name):
            return self.get(InventoryConfig.general_section, option_name)
        else:
            return None


    # Module options methods

    def get_modules_list(self):
        """Returns a list with the Module names located in the config file"""
        modules_list = []

        is_module_option = InventoryConfig.is_module
        for section in self.sections():
            # Check if the section is a module
            if self.has_option(section, is_module_option) and\
                bool(self.get(section, is_module_option)):
                modules_list.append(section)
        return modules_list


    def module_is_installed(self, module_name):
        """Returns True if module_name is installed. False otherwise"""
        return self.has_section(module_name)


    def module_get_enable(self, module_name):
        """
        Returns True if the module with the name module_name is enabled.
        False otherwise.
        Raises InventoryConfig.ModuleNotInstalled if module_name is not installed.
        """
        if self.is_core_module(module_name):
            return True

        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        return bool(self.get(module_name, InventoryConfig.module_enabled))


    def module_set_enable(self, module_name, enable_value=True):
        """
        Sets the module with the name module_name to be enabled if enable_value
        is True.
        Raises InventoryConfig.ModuleNotInstalled if module_name is not installed
        """
        if self.is_core_module(module_name):
            return

        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        self.set(module_name, InventoryConfig.module_enabled, enable_value)


    def module_set_option(self, module_name, option_name, option_value):
        """Sets an option for a given module"""
        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        self.set(module_name, option_name, option_value)


    def module_get_option(self, module_name, option_name):
        """Used to get an option for a given module"""
        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        if self.has_option(module_name, option_name):
            return self.get(module_name, option_name)
        else:
            return None


    def module_set_options(self, module_name, option_dict, overwrite=True):
        """
        Used to set the options in option_dict, which is a dictionary with
        entries of the type [option_name, option_value]. If overwrite is set
        to False, any existing values will not be overwritten.
        """
        if not self.module_is_installed(module_name):
            raise InventoryConfig.ModuleNotInstalled(module_name)

        for option_name in option_dict.keys():
            if not overwrite and self.has_option(module_name, option_name):
                continue
            self.set(module_name, option_name, option_dict[option_name])


    # Private methods

    def _clear_settings(self):
        """Clears the current settings"""
        sections = self.sections()
        for section in sections:
            self.remove_section(section)


    def _set_default_settings(self):
        """Load default fail-save settings"""
        self.add_section(InventoryConfig.general_section)
        self.set(InventoryConfig.general_section, InventoryConfig.log_path,\
                 self._get_default_log_path())
        self.set(InventoryConfig.general_section, InventoryConfig.log_level,\
                 InventoryConfig.default_log_level)


    def _set_default_config_file(self):
        """Sets the default configuration file"""
        pass


    def _get_default_log_path(self):
        """Returns the default log path. Must be implemented"""
        pass


    # Exceptions

    class ModuleNotInstalled(Exception):

        def __init__(self, module_name):
            self.err_message = 'Module ' + str(module_name) + ' not installed'

        def __str__(self):
            return repr(self.err_message)


    class GeneralError(Exception):

        def __init__(self, value):
            self.err_message = str(value)

        def __str__(self):
            return repr(self.err_message)


    class ConfigFile(Exception):

        def __init__(self, value):
            self.err_message = 'Can\'t open ' + str(value)

        def __str__(self):
            return repr(self.err_message)
