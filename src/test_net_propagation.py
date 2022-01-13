#!/usr/bin/python3

import net_propagation
import pytest

"""
 - Importing modules from net_propagation for testing.
 - Importing pytest for test functions.
 - Importing os to force exiting without failed tests (see try/catch 
   surrounding functions which lead to system exits in testing)
"""

"""
===PLEASE READ===
Test functions are organised alphabetically. The tests here pertain to 
net_propagation.py. Every test function has a block comment explaining what it 
does.
"""
# The exit code to be used for tests.
TEST_EXIT_CODE = 255


def test_file_error_handler():
    """
    This function tests the file_error_handler method in the main class. Should
    just run straight through no problem hence why all this method does is run
    that method, errors or exceptions will fail this test for us.
    """
    net_propagation.file_error_handler("test", TEST_EXIT_CODE)
