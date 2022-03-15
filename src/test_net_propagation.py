#!/usr/bin/python3

import net_propagation
import strings
import test_files.strings

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
    script. Currently, the function only calls two other functions, so this
    test uses the bad path in both to run through once. Good paths are tested
    in the two functions own tests.
    """
    arguments = [strings.ARGUMENT_IP_ADDRESS_FILENAME,
                 strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE]
    ip = strings.BLANK_IP
    username = test_files.strings.RANDOM_STRING
    transfer_file_filename = test_files.strings.RANDOM_STRING
    ports = [strings.SSH_PORT, strings.TELNET_PORT,
             strings.WEB_PORT_EIGHTY,
             strings.WEB_PORT_EIGHTY_EIGHTY,
             strings.WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT]
    for port in ports:
        net_propagation.additional_actions(arguments, ip, port, username,
                                           transfer_file_filename)


def test_append_lines_from_file_to_list():
    """
    This function tests the append_lines_from_file_to_list function in the
    net_propagation script. It feeds in a test file, and we check the result it
    returns for validity. Each line is checked independently without a for loop
    for readability in test results i.e. we'll be able to correlate a specific
    line with an error.
    """
    with open(str(test_files.strings.TEST_FILENAME)) as file:
        lines_list = net_propagation.append_lines_from_file_to_list(file)
    assert lines_list[0] == test_files.strings.TEST_LINES[0]
    assert lines_list[1] == test_files.strings.TEST_LINES[1]
    assert lines_list[2] == test_files.strings.TEST_LINES[2]
    assert lines_list[3] == test_files.strings.TEST_LINES[3]
    assert lines_list[4] == test_files.strings.TEST_LINES[4]
    assert lines_list[5] == test_files.strings.TEST_LINES[5]


def test_assigning_values():
    """
    This function tests the assigning_values function in the net_propagation
    script. It uses example arguments to do this stored in strings.py, but
    before it does that the bad path is checked by passing in a single argument
    with no value to get a runtime error.
    """



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
