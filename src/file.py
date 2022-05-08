#!/usr/bin/python3

# Author: @andrewk10

# Importing demo_functions for the demo specific functionality.
import demo_functions
# Importing logging to safely log sensitive, error or debug info.
import logging
# For net_propagation related functionality.
import net_propagation
# Import os for path checking.
import os
# Importing strings for use of the external strings resources.
import strings
# Importing strings_functions for string building functions.
import strings_functions
# Importing subprocess for running commands.
import subprocess


class File:
    """
    Stores a file along with its properties and allows the file to be
    manipulated
    """

    def __init__(self, filename):
        """
        Object parameters being initialised
        :param filename: The filename of the file that needs to be converted to
         a list
        :param filename: The filename of the file, can include the path
        """
        self.filename = filename

    def append_lines_from_file_to_list(self):
        """
        This function will read a file and return the lines (minus the newline
        character) as a list
        :return lines_list: The lines themselves.
        """
        lines_list = []
        with open(self.filename) as file:
            for line in file:
                lines_list.append(line.rstrip())
        return lines_list

    def check_transfer_file(self, arguments, ip, port, login_details):
        """
        This function attempts transferring a user specified file across the
        network. If it succeeds we alert the user and let them know
        transferring the file was a success and over what service. If it is
        unsuccessful then we let the user know it was unsuccessful and over
        what service. Should the user have never asked for a file to be
        transferred over the network then we let them know this process will
        not be done
        :param arguments: The arguments passed in by the user themselves
        :param ip: The IP address we wish to propagate to
        :param port: The port we're propagating through
        :param login_details: The username and password string combo
        """
        if arguments.propagate_file and (str(port) == strings.SSH_PORT):
            transferred = self.transfer_file(ip, port, login_details)
            if transferred:
                logging.info(strings.TRANSFER_SUCCESS_SSH)
            else:
                logging.debug(strings.TRANSFER_FAILURE_SSH)
        else:
            logging.info(strings.DO_NOT_TRANSFER)

    def convert_file_to_list(self):
        """
        This function will convert a given file specified by a filename to a
        list and will then proceed to return that list
        :return file_as_list: The list of the lines from the file
        """
        try:
            file_as_list = self.append_lines_from_file_to_list()
            return file_as_list
        except FileNotFoundError:
            logging.error(strings.FILE_DOES_NOT_EXIST)
            return None

    def file_error_handler(self):
        """
        This function handles errors related to the processing of files.
        """
        logging.error(strings_functions.filename_processing_error(
            self.filename))
        demo_functions.exit_and_show_instructions()

    def file_not_exist(self, ip, port, username, password):
        """
        This function will check whether this file exists on a target
        machine and how it does that is dependent on the port being passed in
        :param ip: IP of the machine we're checking for a file for
        :param port: Port on which we which to check the machine
        :param username: Username to use as part of checking the file
        :param password: Password being used as part of checking the file
        :return check_over_ssh(ip, port, username, password):
        """
        propagator = net_propagation.NetPropagation(username, password, ip,
                                                    port, None, None, None)
        return propagator.check_over_ssh(self.filename)

    def transfer_file(self, ip, port, login_string):
        """
        This function will transfer a given file if the end user has provided
        the appropriate argument, and only when machine login details are found
        :param ip: The IP address to which the file should be transferred
        for SSH. It handles the transfer of this file differently depending on
        whether the port value given is an SSH port
        :param port: The port over which the file should be transferred
        :param login_string: The username and password needed for the transfer
        of the file over the given service
        :return True: The transfer of the file is a success
        :return False: The transfer of the file is unsuccessful
        """
        login_string_split = login_string.split(strings.COLON)
        try:
            print(strings.RSA_AND_PROMPT)
            subprocess.call(strings_functions.scp_command_string(
                port, login_string_split[0], ip, self.filename), shell=True)
            return True
        except ConnectionRefusedError:
            return False

    def validate_file_exists(self):
        """
        This function checks if a file exists given a set filename and if it
        doesn't we alert the user with an error, show the help screen and exit
        gracefully
        """
        if not os.path.exists(self.filename):
            logging.error(strings.FILE_DOES_NOT_EXIST)
            demo_functions.exit_and_show_instructions()
