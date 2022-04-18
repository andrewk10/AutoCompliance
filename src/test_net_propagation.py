#!/usr/bin/python3

# Importing argparse for the handling of passed in arguments.
import argparse
# Importing file for file based functionality
import file
# Importing net_propagation for testing.
import net_propagation
# Importing strings for common string resources.
import strings
# Importing strings_functions for dynamic string functionality.
import strings_functions


def test_additional_actions():
    """
    This function tests the additional_actions function in the net_propagation
    script. Currently, the function only calls two other functions, so this
    test uses the bad path in both to run through once. Good paths will be
    tested in the two functions own tests.
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


def test_append_lines_from_file_to_list():
    """
    This function tests the append_lines_from_file_to_list function in the
    net_propagation script. It feeds in a test file, and we check the result it
    returns for validity. Each line is checked independently without a for loop
    for readability in test results i.e. we'll be able to correlate a specific
    line with an error.
    """
    test_file = file.File(strings.FILE)
    lines_list = test_file.append_lines_from_file_to_list()
    assert lines_list[0] == strings.LINES[0]
    assert lines_list[1] == strings.LINES[1]
    assert lines_list[2] == strings.LINES[2]
    assert lines_list[3] == strings.LINES[3]
    assert lines_list[4] == strings.LINES[4]
    assert lines_list[5] == strings.LINES[5]


def test_check_over_ssh():
    """
    This function tests the check_check_over_ssh function, it will always fail
    for now until I figure out how to mock a file present across an SSH
    connection.
    """
    test_file = file.File(strings.FILE)
    propagator = net_propagation.NetPropagation(
        strings.ADMIN, strings.ADMIN, strings.TEST_IP, strings.SSH_PORT, None,
        None, None)
    assert propagator.check_over_ssh(test_file.filename) is True


def test_convert_file_to_list():
    """
    This function tests the convert_file_to_list function, it does this by
    passing in one valid filename and one invalid filename.
    """
    test_file = file.File(strings.IP_LIST_SHORT)
    assert test_file.convert_file_to_list() is not None
    test_file = file.File(strings.PWDS_LIST_SHORT)
    assert test_file.convert_file_to_list() is not None
    test_file = file.File(strings.TEST_IP)
    assert test_file.convert_file_to_list() is None


def test_file_error_handler(capfd):
    """
    This function tests the file_error_handler function. Should just run
    straight through no problem hence why all this function does is run that
    function and check what shows up in the console, errors or exceptions will
    fail this test for us
    :param capfd: Parameter needed to capture log output.
    """
    test_file = file.File(strings.FILE)
    test_file.file_error_handler()
    out, err = capfd.readouterr()
    assert out == strings_functions.help_output() + "\n" + strings.EXITING + \
           "\n"
