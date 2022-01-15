#!/usr/bin/python3

import net_propagation
import strings
import pytest

"""
 - Importing net_propagation for testing.
 - Importing strings for common string resources.
 - Importing pytest for test functionality.
"""

"""
===PLEASE READ===
Test functions are organised alphabetically. The tests here pertain to 
net_propagation.py. Every test function has a block comment explaining what it 
does.
"""


def test_additional_attacks():
    """
    This function tests the additional_attacks method in the main class. The
    goal is to check every service for both good paths and bad paths.
    """
    # TODO: Finish this test. Check assert for console output in the bad path
    #  and start the good path.
    arguments = ["-t", "-d"]
    ip = "0.0.0.0"
    port = "9999"
    username = "test"
    transfer_file_filename = "test"
    services = ["ssh", "telnet", "web login"]
    for service in services:
        net_propagation.additional_attacks(arguments, ip, port, username,
                                           transfer_file_filename, service)


def test_file_error_handler(capfd):
    """
    This function tests the file_error_handler function. Should just run
    straight through no problem hence why all this function does is run that
    function and check what shows up in the console, errors or exceptions will
    fail this test for us.
    """
    net_propagation.file_error_handler("test")
    out, err = capfd.readouterr()
    assert out == strings.filename_processing_error("test") + "\n" \
           + strings.PLS_HELP + "\n" + strings.EXITING + "\n"
