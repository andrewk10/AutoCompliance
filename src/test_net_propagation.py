#!/usr/bin/python3
# TODO: Implement proper logging for tests. Not much point if we don't know
#  what's going on. :) In fact, implement it wherever it can be... (Andrew)

import net_propagation
import strings
import logging

"""
 - Importing net_propagation for testing.
 - Importing strings for common string resources.
"""

"""
===PLEASE READ===
Test functions are organised alphabetically. The tests here pertain to
net_propagation.py. Every test function has a block comment explaining what it
does.
"""


def test_additional_actions():
    """
    This function tests the additional_actions function in the net_propagation
    script. The goal is to check every service for both good paths and bad
    paths.
    """
    logging.info(strings.ASSIGNING_ARGUMENTS)
    arguments = [strings.ARGUMENT_IP_ADDRESS_FILENAME,
                 strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE]
    logging.info(strings.SETTING_BLANK_IP)
    ip = strings.BLANK_IP
    username = strings.TEST
    transfer_file_filename = strings.TEST
    ports = [strings.SSH_PORT, strings.TELNET_PORT,
             strings.WEB_PORT_EIGHTY,
             strings.WEB_PORT_EIGHTY_EIGHTY,
             strings.WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT]
    # TODO: Finish this test by checking assert for console output in the bad
    #  path and start the good path. (Andrew)
    for port in ports:
        net_propagation.additional_actions(arguments, ip, port, username,
                                           transfer_file_filename)


def test_append_lines_from_file_to_list():
    """
    This function tests the append_lines_from_file_to_list function in the
    net_propagation script. It feeds in a test file, and we check the result it
    returns for validity.
    """
    lines_list = net_propagation.append_lines_from_file_to_list(
        strings.TEST_FILENAME)
    logging.info(lines_list)


def test_exit_and_show_instructions(capfd):
    """
    This function tests the exit_and_show_instructions function.
    Should just run straight through no problem hence why all this function
    does is run that function and check what shows up in the console, errors or
    exceptions will fail this test for us
    :param capfd: Parameter needed to capture log output.
    """
    net_propagation.exit_and_show_instructions()
    out, err = capfd.readouterr()
    assert out == strings.PLS_HELP + "\n" + strings.EXITING + "\n"


def test_file_error_handler(capfd):
    """
    This function tests the file_error_handler function. Should just run
    straight through no problem hence why all this function does is run that
    function and check what shows up in the console, errors or exceptions will
    fail this test for us
    :param capfd: Parameter needed to capture log output.
    """
    net_propagation.file_error_handler()
    out, err = capfd.readouterr()
    assert out == strings.FILENAME_PROCESSING_ERROR + "\n" \
           + strings.PLS_HELP + "\n" + strings.EXITING + "\n"
