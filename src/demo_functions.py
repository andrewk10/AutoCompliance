#!/usr/bin/python3

# Author: @andrewk10

# Importing file for file based functionality.
import file
# Importing logging to safely log sensitive, error or debug info.
import logging
# Importing strings for use of the external strings resources.
import strings
# Importing strings_functions for string building functions.
import strings_functions


class DemoFunctions:
    """
    This class houses the functionality that is used exclusively for demo
    purposes.
    """

    def __init__(self, arguments):
        """
        Object parameters being initialised
        :param arguments: User defined arguments
        """
        self.arguments = arguments

    def assigning_values(self):
        """
        This function will read in the target ports, target username and
        passwords filename from the user and if the user specified an ip
        addresses file it will read that and return it alongside all the other
        values
        :return ip_list: The list of IP addresses contained in the given file
        :return target_ports: The selection of ports to target
        :return target_username: The username that will be used for actions
        :return passwords_filename: The filename of the passwords file
        :return None: If an error occurs
        """
        # Out of scope initialisation for return later.
        ip_list = None
        if self.arguments.target:
            ip_addresses_filename = self.arguments.target
            ip_address_file = file.File(ip_addresses_filename)
            ip_list = ip_address_file.convert_file_to_list()
        else:
            logging.debug(strings.IP_FILENAME_NOT_FOUND)

        if self.arguments.password_file:
            return ip_list, self.arguments.ports, self.arguments.username, \
                   self.arguments.password_file

        logging.error(strings.FILE_DOES_NOT_EXIST)
        return None

    def checking_arguments(self):
        """
        This function checks if the arguments are appropriately given and if
        they're not it calls the help function and gracefully exits. There's
        also a check for the help argument itself. It'll try to assign the \
        values if the proper arguments are given, and they're valid
        :return values[0]: List of IP addresses
        :return values[1]: Ports and subsequently services to target
        :return values[2]: Username to target
        :return values[3]: Filename for a file containing passwords
        :return None: If the values can't be assigned.
        """
        if (self.arguments.target or self.arguments.lan) and \
                self.arguments.ports and self.arguments.username:
            try:
                values = self.assigning_values()
                if values is not None and not self.arguments.lan:
                    return values[0], values[1], values[2], values[3]
                if values is not None and self.arguments.lan:
                    return strings.SPACE, values[1], values[2], values[3]
                logging.error(strings.FAILED_ASSIGNING_VALUES)
                return None
            except RuntimeError:
                logging.error(strings.FAILED_ASSIGNING_VALUES)
                return None
        else:
            logging.error(strings.PARAMETER_MISUSE)
            return None


def exit_and_show_instructions():
    """
    This function will print the help screen and show an exit prompt.
    """
    print(strings_functions.help_output())
    print(strings.EXITING)
