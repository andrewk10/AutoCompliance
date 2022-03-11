#!/usr/bin/python3
import logging
import net_propagation
import strings
import sys

"""
 - Importing logging to safely log sensitive, error or debug info.
 - Importing net_propagation for propagating across the network.
 - Importing strings for use of the external strings resources.
 - Importing sys to make OS calls and use OS level utilities.
"""

"""
===PLEASE READ===
This main function itself has more  specific, low level commenting.
"""


def main():
    """
    This main function is what initially runs when AutoCompliance runs.
    """
    # These arguments are passed in by the end user.
    arguments = sys.argv

    # If there is no arguments then just print the help menu and exit.
    if arguments.__len__():
        net_propagation.exit_and_show_instructions()
        sys.exit(-1)

    # Just initialising this for use later.
    transfer_file_filename = strings.BLANK_STRING

    # Validating and assigning values based on arguments passed in.
    ip_list, target_ports, target_username, passwords_filename = \
        net_propagation.checking_arguments(arguments)

    # The end user specified a local scan must be executed, the result of the
    # local scan will extend the current ip_list.
    if strings.ARGUMENT_SCAN_LOCAL_NETWORKS in arguments:
        logging.info(strings.PERFORMING_LOCAL_SCAN)
        ip_list.extend(net_propagation.gathering_local_ips(ip_list))

    try:
        # Here I made sure the user actually gave a valid file for the
        # passwords list. If they have...
        net_propagation.validate_file_exists(passwords_filename)
        # A list of passwords is created.
        password_list = \
            net_propagation.convert_file_to_list(passwords_filename)
    except RuntimeError:
        # File doesn't exist, alert the user and exit gracefully, so
        # they can possibly fix their mistake.
        net_propagation.file_error_handler()
        sys.exit(-1)

    # If the user wants to transfer a file, this stuff should be done...
    if strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE in arguments:
        try:
            # Again making sure the transfer file actually exits, just like
            # the password file above.
            net_propagation.validate_file_exists(transfer_file_filename)
            # If it does though we assign the filename to the name out of scope
            # above.
            transfer_file_filename = arguments[arguments.index(
                strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE) + 1]
        except RuntimeError:
            # File doesn't exist, throw an error and give the user a chance to
            # try again.
            net_propagation.file_error_handler()
            sys.exit()
    # Removing duplicate entries in the IP address list, can come from
    # combining local scan with given IP addresses in an ip address file for
    # example.
    # TODO: Find a way to fix the duplicates issue, instead of this workaround.
    ip_list = list(dict.fromkeys(ip_list))
    # Removing IPs from the IP list that can't be pinged from the host machine
    # of the script.
    ip_list = net_propagation.remove_unreachable_ips(ip_list)
    # Getting a list of ports by splitting the target ports specified by the
    # user on the comma.
    ports = target_ports.split(strings.COMMA)
    # Cycling through every IP in the IP list...
    for ip in ip_list:
        # And then using all user specified ports against that specific IP...
        for port in ports:
            # Try to spread using services and actions.
            net_propagation.try_action(ip, port, target_username,
                                       password_list, transfer_file_filename,
                                       arguments)


main()
