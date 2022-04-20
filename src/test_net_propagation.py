#!/usr/bin/python3

# Importing argparse for the handling of passed in arguments.
import argparse
# Importing file for file based functionality
import file
# Importing net_propagation for testing.
import net_propagation
# Importing strings for common string resources.
import strings


def test_additional_actions():
    """
    This function tests the additional_actions function in the net_propagation
    script. Currently, the function only calls two other functions, so this
    test uses the bad path in both to run through once. Good paths will be
    tested in the two functions own tests eventually
    """
    propagator = net_propagation.NetPropagation(
        strings.RANDOM_STRING, None, strings.TEST_IP, None, None, None, None)
    transfer_file = file.File(strings.RANDOM_STRING)
    propagation_script = file.File(strings.RANDOM_STRING)

    # Argument parser for handling arguments.
    parser = argparse.ArgumentParser(description=strings.DESCRIPTION)
    # Adding the target  file option to the parser.
    parser.add_argument(
        strings.IP_FILE_OPT_SHORT, strings.IP_FILE_OPT_LONG,
        dest='target', help=strings.IP_FILE_HELP, type=str)
    # Adding the username option to the parser.
    parser.add_argument(
        strings.USERNAME_OPT_SHORT, strings.USERNAME_OPT_LONG,
        dest='username', help=strings.USERNAME_HELP, type=str)
    # Adding the password file option to the parser.
    parser.add_argument(
        strings.PW_FILE_OPT_SHORT, strings.PW_FILE_OPT_LONG,
        dest="password_file", help=strings.PW_FILE_HELP, type=str)
    # Adding the port option to the parser.
    parser.add_argument(
        strings.PORT_OPT_SHORT, strings.PORT_OPT_LONG,
        dest='ports', help=strings.PORT_HELP, type=str)
    # Adding the lan option to the parser.
    parser.add_argument(
        strings.LAN_OPT_SHORT, strings.LAN_OPT_LONG,
        dest='lan', help=strings.LAN_HELP, type=str)
    # Adding the propagate option to the parser.
    parser.add_argument(
        strings.PROP_OPT_SHORT, strings.PROP_OPT_LONG,
        dest='propagate', help=strings.PROP_HELP, type=str)
    # Adding the transfer file option to the parser.
    parser.add_argument(
        strings.PROP_FILE_OPT_SHORT, strings.PROP_FILE_OPT_LONG,
        dest='propagate_file', help=strings.PROP_FILE_HELP, type=str)

    # Parsing the arguments.
    arguments = parser.parse_args()
    # Hard-coding necessary arguments
    arguments.target = strings.IP_LIST_SHORT
    arguments.ports = strings.ALL_PORTS
    arguments.username = strings.ADMIN
    arguments.password_file = strings.PWDS_LIST_SHORT
    arguments.propagate_file = strings.FILE
    ports = [strings.SSH_PORT, strings.WEB_PORT_EIGHTY,
             strings.WEB_PORT_EIGHTY_EIGHTY,
             strings.WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT]
    for port in ports:
        propagator.port = port
        propagator.additional_actions(transfer_file, propagation_script,
                                      arguments)


def test_check_over_ssh():
    """
    This function tests the check_check_over_ssh function, only tests the bad
    path for now
    """
    test_file = file.File(strings.FILE)
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.TEST_IP, strings.SSH_PORT, None,
        None, None)
    assert propagator.check_over_ssh(test_file.filename) is True


def test_connect_ssh_client():
    """
    This function tests the connect_ssh_client function, only tests the bad
    path for now
    """
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.TEST_IP, strings.SSH_PORT, None,
        None, None)
    assert propagator.connect_ssh_client() is False


def test_connect_web():
    """
    This function tests the connect_web function, only tests the bad path for
    now
    """
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.TEST_IP, strings.SSH_PORT, None,
        None, None)
    assert propagator.connect_ssh_client() is False


def test_cycle_through_subnet():
    """
    This function tests the cycle_through_subnet function
    """
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.TEST_IP, strings.SSH_PORT,
        strings.LOOPBACK, strings.LOOPBACK_IP_AS_LIST, None)
    assert propagator.cycle_through_subnet() == strings.TEST_IP_LIST
