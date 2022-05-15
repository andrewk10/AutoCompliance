#!/usr/bin/python3

# Author: @andrewk10

# Importing file for file based functionality
import file
# Importing strings for common string resources.
import strings
# Importing strings_functions for dynamic string functionality.
import strings_functions
# Importing demo functions for the parsing of arguments.
import demo_functions


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


def test_check_transfer_file():
    """
    This function tests the check_transfer_file function. Only runs through the
    function with web and ssh ports making sure no errors are encountered.
    """
    test_file = file.File(strings.IP_LIST_SHORT)
    arguments = demo_functions.parse_arguments([strings.PROP_OPT_SHORT])
    test_file.check_transfer_file(
        arguments, strings.LOOPBACK_IP, strings.SSH_PORT, strings.ADMIN)
    test_file.check_transfer_file(
        arguments, strings.LOOPBACK_IP, strings.WEB_PORT_EIGHTY, strings.ADMIN)


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
    fail this test for us as well as a change to the string function itself
    :param capfd: Parameter needed to capture log output.
    """
    test_file = file.File(strings.FILE)
    test_file.file_error_handler()
    out, err = capfd.readouterr()
    assert out == strings_functions.help_output() + "\n" + strings.EXITING + \
           "\n"
