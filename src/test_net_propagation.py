#!/usr/bin/python3
# TODO: Finish this test by checking assert for console output in the bad path
#  and start the good path. (Andrew)
# TODO: Implement proper logging for tests. Not much point if we don't know
#  what's going on. :) In fact, implement it wherever it can be... (Andrew)

import net_propagation
import strings

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
    This function tests the additional_actions method in the net_propagation
    script. The goal is to check every service for both good paths and bad
    paths.
    """
    arguments = [strings.ARGUMENT_IP_ADDRESS_FILENAME,
                 strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE]
    ip = strings.BLANK_STRING
    username = strings.TEST
    transfer_file_filename = strings.TEST
    ports = [strings.SSH_PORT, strings.TELNET_PORT, strings.WEB_PORT_EIGHTY,
             strings.WEB_PORT_EIGHTY_EIGHTY,
             strings.WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT]
    for port in ports:
        net_propagation.additional_actions(arguments, ip, port, username,
                                           transfer_file_filename)


def test_file_error_handler(capfd):
    """
    This function tests the file_error_handler function. Should just run
    straight through no problem hence why all this function does is run that
    function and check what shows up in the console, errors or exceptions will
    fail this test for us.
    :param capfd: Parameter needed to capture log output.
    """
    # TODO: Is this test really needed? Investigate removal.
    net_propagation.file_error_handler()
    out, err = capfd.readouterr()
    assert out == strings.FILENAME_PROCESSING_ERROR + "\n" \
           + strings.PLS_HELP + "\n" + strings.EXITING + "\n"
