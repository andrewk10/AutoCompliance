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


def test_additional_attacks(args, ip, port, bruteforce,
                            transfer_file_filename, service):
    """
    This function tests the additional_attacks method in the main class.
    """


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
