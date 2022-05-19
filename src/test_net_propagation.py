#!/usr/bin/python3

# Author: @andrewk10

# Importing demo_functions for demo specific functionality.
import demo_functions
# Importing file for file based functionality
import file
# Importing logging to log the ping command fails
import logging
# Importing net_propagation for testing
import net_propagation
# Importing strings for common string resources
import strings
# Importing subprocess to run the ping command where needed
import subprocess

# Uncomment this test if needed. Warning, it's very slow.
# def test_additional_actions():
#     """
#     This function tests the additional_actions function in the net_propagation
#     script. Currently, the function only calls two other functions, so this
#     test uses the bad path in both to run through once. Good paths will be
#     tested in the two functions own tests eventually
#     """
#     propagator = net_propagation.NetPropagation(
#         strings.RANDOM_STRING, None, strings.TEST_IP, None, None, None, None)
#     transfer_file = file.File(strings.RANDOM_STRING)
#     propagation_script = file.File(strings.RANDOM_STRING)
#
#     # Parsing and hard-coding necessary arguments
#     arguments = demo_functions.parse_arguments([
#         strings.IP_FILE_OPT_SHORT, strings.IP_LIST_SHORT,
#         strings.PORT_OPT_SHORT, strings.ALL_PORTS, strings.USERNAME_OPT_SHORT,
#         strings.ADMIN, strings.PW_FILE_OPT_SHORT, strings.PWDS_LIST_SHORT,
#         strings.PROP_FILE_OPT_SHORT, strings.FILE])
#
#     # arguments.target = strings.IP_LIST_SHORT
#     # arguments.ports = strings.ALL_PORTS
#     # arguments.username = strings.ADMIN
#     # arguments.password_file = strings.PWDS_LIST_SHORT
#     # arguments.propagate_file = strings.FILE
#     ports = [strings.SSH_PORT, strings.WEB_PORT_EIGHTY]
#     for port in ports:
#         propagator.port = port
#         propagator.additional_actions(transfer_file, propagation_script,
#                                       arguments)


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
        strings.ADMIN, strings.ADMIN, strings.TEST_IP, strings.WEB_PORT_EIGHTY,
        None, None, None)
    assert propagator.connect_web() is False


def test_cycle_through_subnet():
    """
    This function tests the cycle_through_subnet function
    """
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.TEST_IP, strings.SSH_PORT,
        strings.LOOPBACK, strings.LOOPBACK_IP_AS_LIST, None)
    propagator.cycle_through_subnet()
    assert propagator.ip_list == strings.TEST_IP_LIST


def test_gathering_local_ips():
    """
    This function tests the gathering_local_ips function which is going to have
    a different result no matter what machine it runs on, hence no assertion
    since no assumption can be made
    """
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.TEST_IP, strings.SSH_PORT,
        strings.LOOPBACK, strings.LOOPBACK_IP_AS_LIST, None)
    propagator.gathering_local_ips()


def test_is_reachable_ip():
    """
    This function tests the is_ip_reachable function good and bad paths, good
    path by using the default loopback IP address and the bad path by using a
    reserved local IP address.
    """
    try:
        # Need to do a quick test ping to ensure the ping command is actually
        # available, this is being done on the test level as this test assumes
        # ping is in fact available.
        command = [strings.PING, strings.PING_ARGUMENT, strings.ONE, str(
            strings.LOOPBACK_IP)]
        subprocess.call(command)
        propagator = net_propagation.NetPropagation(
            strings.ADMIN, strings.ADMIN, strings.LOOPBACK_IP,
            strings.SSH_PORT,
            strings.LOOPBACK, strings.LOOPBACK_IP_AS_LIST, None)
        assert propagator.is_reachable_ip() is True
        propagator.ip = strings.TEST_IP_FAIL
        assert propagator.is_reachable_ip() is False
    except FileNotFoundError:
        # If ping isn't available, no worries, we handle it
        logging.debug(strings.PING_CMD_NOT_FOUND)


def test_propagate_script():
    """
    This function tests the propagate_script function but only the bad path.
    """
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.LOOPBACK_IP, strings.SSH_PORT,
        strings.LOOPBACK, strings.LOOPBACK_IP_AS_LIST, None)
    assert propagator.propagate_script(file.File(strings.FILE)) is False


def test_propagating():
    """
    This function tests the propagating function but only the bad path.
    """
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.LOOPBACK_IP, strings.SSH_PORT,
        strings.LOOPBACK, strings.LOOPBACK_IP_AS_LIST, None)

    # Parsing the arguments and hard-coding necessary arguments
    arguments = demo_functions.parse_arguments([
        strings.IP_FILE_OPT_SHORT, strings.IP_LIST_SHORT,
        strings.PORT_OPT_SHORT, strings.ALL_PORTS, strings.USERNAME_OPT_SHORT,
        strings.ADMIN, strings.PW_FILE_OPT_SHORT, strings.PWDS_LIST_SHORT,
        strings.PROP_FILE_OPT_SHORT, strings.FILE, strings.PROP_OPT_SHORT])

    propagator.propagating(file.File(strings.FILE), arguments)


def test_remove_unreachable_ips():
    """
    This function tests the remove_unreachable_ips function but only the bad
    path.
    """
    try:
        # Need to do a quick test ping to ensure the ping command is actually
        # available, this is being done on the test level as this test assumes
        # ping is in fact available.
        command = [strings.PING, strings.PING_ARGUMENT, strings.ONE, str(
            strings.LOOPBACK_IP)]
        subprocess.call(command)
        propagator = net_propagation.NetPropagation(
            strings.ADMIN, strings.ADMIN, strings.LOOPBACK_IP,
            strings.SSH_PORT, strings.LOOPBACK,
            strings.LOOPBACK_AND_FAIL_IP_AS_LIST, None)
        propagator.remove_unreachable_ips()
        # Weird quirk, can't use LOOPBACK_IP_AS_LIST here if
        # test_cycle_through_subnet or gathering_local_ips is used.
        assert propagator.ip_list == strings.LOOPBACK_IP_AS_LIST_REMOVE
    except FileNotFoundError:
        # If ping isn't available, no worries, we handle it
        logging.debug(strings.PING_CMD_NOT_FOUND)


def test_scan_port():
    """
    This function tests the scan port function
    """
    # Good path
    propagator = net_propagation.NetPropagation(
        None, None, strings.LOOPBACK_IP, strings.SSH_PORT, None, None, None)
    assert not propagator.scan_port()
    # Bad Path
    propagator = net_propagation.NetPropagation(
        None, None, None, None, None, None, None)
    assert not propagator.scan_port()


def test_try_password_for_function():
    """
    This function tests the try_password_for_function function
    """
    # Try SSH first
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.LOOPBACK_IP, strings.SSH_PORT,
        None, None, None)
    assert propagator.try_password_for_service() is False

    # Try Web next
    propagator.port = strings.WEB_PORT_EIGHTY
    assert propagator.try_password_for_service() is False


def test_try_sign_in():
    """
    This function tests the try_sign_in function
    """
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.LOOPBACK_IP, strings.SSH_PORT,
        None, None, [strings.ADMIN])
    assert propagator.try_sign_in() == (None, strings.SSH_LOWERCASE)

    propagator.port = strings.WEB_PORT_EIGHTY
    assert propagator.try_sign_in() == (None, strings.WEB_LOGIN)

    propagator.port = strings.WEB_PORT_EIGHTY_EIGHTY
    assert propagator.try_sign_in() == (None, strings.WEB_LOGIN)

    propagator.port = strings.WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT
    assert propagator.try_sign_in() == (None, strings.WEB_LOGIN)
