#!/usr/bin/python3
import net_propagation
"""
===PLEASE READ===
Functions are organised alphabetically with the main function specified last.
Every function besides the main function has a block comment explaining what it
does, the main function itself has more specific, low level commenting.
"""


class TestMain:
    def test_file_error_handler():
        """
        This function tests the file_error_handler method in the main class.
        Should just run straight through no problem hence why all this method
        does is run that method, errors or exceptions will fail this test for
        us.
        """
        main.file_error_handler("test")
